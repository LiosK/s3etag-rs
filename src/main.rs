use std::num::NonZeroUsize;
use std::{error, fmt, fs, io, mem, path, process};

#[cfg(unix)]
use std::os::unix::ffi::OsStrExt as _;

fn main() -> process::ExitCode {
    const PROG: &str = env!("CARGO_PKG_NAME");
    let matches = clap::Command::new(PROG)
        .version(env!("CARGO_PKG_VERSION"))
        .about(env!("CARGO_PKG_DESCRIPTION"))
        .arg(
            clap::Arg::new("files")
                .required(true)
                .value_name("FILE")
                .value_parser(clap::value_parser!(path::PathBuf))
                .action(clap::ArgAction::Append)
                .help("filenames"),
        )
        .arg(
            clap::Arg::new("chunksize")
                .long("chunksize")
                .value_name("SIZE")
                .value_parser(parse_chunksize)
                .default_value("8MB")
                .help(CHUNKSIZE_HELP),
        )
        .arg(
            clap::Arg::new("use_mmap")
                .long("no-mmap")
                .action(clap::ArgAction::SetFalse)
                .help("disable memory-mapped I/O in reading files"),
        )
        .get_matches();

    let mut exit_code = process::ExitCode::SUCCESS;
    let mut writer = io::LineWriter::new(io::stdout().lock());
    let mut buffer = match matches.get_one("use_mmap") {
        Some(&true) => None,
        _ => Some(vec![0u8; 64 * 1024].into_boxed_slice()),
    };
    let chunksize = *matches.get_one::<NonZeroUsize>("chunksize").unwrap();
    for filename in matches.get_many::<path::PathBuf>("files").unwrap() {
        #[cfg(feature = "libssl")]
        let hasher = EtagHasher::<libssl::Md5>::new(chunksize);
        #[cfg(not(feature = "libssl"))]
        let hasher = EtagHasher::<md5::Md5>::new(chunksize);

        if let Err(e) = process_file(filename, hasher, &mut writer, buffer.as_deref_mut()) {
            eprintln!("error: {}: {}", filename.display(), e);
            exit_code = process::ExitCode::FAILURE;
        }
    }
    exit_code
}

const CHUNKSIZE_HELP: &str =
    "multipart_chunksize used for upload in bytes or with a size suffix KB, MB, GB, or TB";

/// Parses the chunksize argument.
fn parse_chunksize(s: &str) -> Result<NonZeroUsize, Box<dyn error::Error + Sync + Send>> {
    let (num, unit) = match s.find(|c: char| !c.is_ascii_digit()) {
        None => (s, Ok(1usize)),
        Some(pos) => (
            &s[..pos],
            match &s[pos..] {
                "KB" => Ok(1 << 10),
                "MB" => Ok(1 << 20),
                "GB" => Ok(1 << 30),
                "TB" => Ok(1 << 40),
                _ => Err("unknown size suffix".to_owned()),
            },
        ),
    };
    num.parse::<NonZeroUsize>()?
        .checked_mul(unit?.try_into()?)
        .ok_or_else(|| "too large chunksize".to_owned().into())
}

/// Computes and prints the Etag for a file.
fn process_file(
    filename: &path::Path,
    mut hasher: EtagHasher<impl Md5Hasher>,
    writer: &mut impl io::Write,
    fread_buffer: Option<&mut [u8]>,
) -> io::Result<()> {
    let mut file = fs::File::open(filename)?;

    match fread_buffer {
        // use mmap if no buffer is supplied
        None => {
            let mm = unsafe { memmap2::Mmap::map(&file)? };
            #[cfg(unix)]
            mm.advise(memmap2::Advice::Sequential)?;
            hasher.update(mm);
        }
        // use fread otherwise
        Some(buffer) => loop {
            match io::Read::read(&mut file, buffer) {
                Ok(0) => break,
                Ok(n) => hasher.update(&buffer[..n]),
                Err(ref e) if e.kind() == io::ErrorKind::Interrupted => (),
                Err(e) => return Err(e),
            }
        },
    }

    write!(writer, "{:<39} ", hasher.finalize())?;

    #[cfg(unix)]
    writer.write_all(filename.as_os_str().as_bytes())?;
    #[cfg(not(unix))]
    write!(writer, "{}", filename.display())?;

    writer.write_all(b"\n")
}

trait Md5Hasher: Default {
    type Output: AsRef<[u8]> + Into<[u8; 16]>;

    fn update(&mut self, data: impl AsRef<[u8]>);

    fn finalize(self) -> Self::Output;

    fn finalize_reset(&mut self) -> Self::Output {
        mem::take(self).finalize()
    }
}

#[derive(Debug)]
struct EtagHasher<H> {
    chunksize: NonZeroUsize,
    n_chunks: usize,
    hasher_whole: H,
    hasher_chunk: H,
    current_capacity: usize,
}

impl<H: Md5Hasher> EtagHasher<H> {
    fn new(chunksize: NonZeroUsize) -> Self {
        Self {
            chunksize,
            n_chunks: 0,
            hasher_whole: Default::default(),
            hasher_chunk: Default::default(),
            current_capacity: chunksize.into(),
        }
    }

    fn update(&mut self, data: impl AsRef<[u8]>) {
        let mut buf = data.as_ref();
        assert!(self.current_capacity > 0);
        while buf.len() >= self.current_capacity {
            let used = self.current_capacity;
            self.hasher_chunk.update(&buf[..used]);
            self.n_chunks += 1;
            self.hasher_whole.update(self.hasher_chunk.finalize_reset());
            self.current_capacity = self.chunksize.into();
            buf = &buf[used..];
        }
        self.hasher_chunk.update(buf);
        self.current_capacity -= buf.len();
    }

    fn finalize(mut self) -> impl fmt::Display {
        struct Etag<D>(D, usize);
        impl<D: AsRef<[u8]>> fmt::Display for Etag<D> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                use fmt::Write as _;
                let mut buf = arrayvec::ArrayString::<64>::new();
                for e in self.0.as_ref() {
                    write!(buf, "{:02x}", e)?;
                }
                if self.1 > 1 {
                    write!(buf, "-{}", self.1)?;
                }
                fmt::Display::fmt(buf.as_str(), f)
            }
        }

        assert!(self.current_capacity <= self.chunksize.into());
        let has_partial_chunk = self.current_capacity < self.chunksize.into();
        if self.n_chunks == 0 || (self.n_chunks == 1 && !has_partial_chunk) {
            Etag(self.hasher_chunk.finalize(), 1)
        } else {
            if has_partial_chunk {
                self.n_chunks += 1;
                self.hasher_whole.update(self.hasher_chunk.finalize());
            }
            Etag(self.hasher_whole.finalize(), self.n_chunks)
        }
    }
}

#[cfg(feature = "libssl")]
mod libssl {
    use openssl::{md::Md, md_ctx::MdCtx};

    pub struct Md5(MdCtx);

    impl Default for Md5 {
        fn default() -> Self {
            let mut ctx = MdCtx::new().expect("libssl error");
            ctx.digest_init(Md::md5()).expect("libssl error");
            Self(ctx)
        }
    }

    impl super::Md5Hasher for Md5 {
        type Output = [u8; 16];

        fn update(&mut self, data: impl AsRef<[u8]>) {
            self.0.digest_update(data.as_ref()).expect("libssl error");
        }

        fn finalize(mut self) -> Self::Output {
            let mut buffer = [0; 16];
            self.0.digest_final(&mut buffer).expect("libssl error");
            buffer
        }
    }
}

#[cfg(not(feature = "libssl"))]
impl Md5Hasher for md5::Md5 {
    type Output = md5::digest::Output<Self>;

    fn update(&mut self, data: impl AsRef<[u8]>) {
        md5::Digest::update(self, data)
    }

    fn finalize(self) -> Self::Output {
        md5::Digest::finalize(self)
    }

    fn finalize_reset(&mut self) -> Self::Output {
        md5::Digest::finalize_reset(self)
    }
}
