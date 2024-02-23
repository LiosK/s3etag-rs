use std::{error, fmt, fs, io, num::NonZeroUsize, path, process};

#[cfg(unix)]
use std::os::unix::ffi::OsStrExt as _;

use md5::Digest as _;

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
    let chunksize = *matches.get_one::<NonZeroUsize>("chunksize").unwrap();
    let use_mmap = *matches.get_one::<bool>("use_mmap").unwrap_or(&false);
    for filename in matches.get_many::<path::PathBuf>("files").unwrap() {
        let hasher = EtagHasher::new(chunksize);
        if let Err(e) = process_file(filename, hasher, &mut writer, use_mmap) {
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
        None => (s, Ok(1)),
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
        .checked_mul(unit?.try_into().unwrap())
        .ok_or_else(|| "too large chunksize".to_owned().into())
}

/// Computes and prints the Etag for a file.
fn process_file(
    filename: &path::Path,
    mut hasher: EtagHasher,
    writer: &mut impl io::Write,
    use_mmap: bool,
) -> io::Result<()> {
    let mut file = fs::File::open(filename)?;

    if use_mmap {
        let mm = unsafe { memmap2::Mmap::map(&file)? };
        #[cfg(unix)]
        mm.advise(memmap2::Advice::Sequential)?;
        hasher.update(mm);
    } else {
        io::copy(&mut file, &mut hasher)?;
    }

    let (n_chunks, digest) = hasher.finalize();
    if n_chunks > 1 {
        write!(writer, "{:032x}-{:<6} ", digest, n_chunks)?;
    } else {
        write!(writer, "{:032x}        ", digest)?;
    }

    #[cfg(unix)]
    writer.write_all(filename.as_os_str().as_bytes())?;
    #[cfg(not(unix))]
    write!(writer, "{}", filename.display())?;

    writer.write_all(b"\n")
}

#[derive(Debug)]
struct EtagHasher {
    chunksize: NonZeroUsize,
    n_chunks: usize,
    hasher_whole: md5::Md5,
    hasher_chunk: md5::Md5,
    current_capacity: usize,
}

impl EtagHasher {
    fn new(chunksize: NonZeroUsize) -> Self {
        Self {
            chunksize,
            n_chunks: 0,
            hasher_whole: md5::Md5::new(),
            hasher_chunk: md5::Md5::new(),
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

    fn finalize(mut self) -> (usize, impl fmt::LowerHex) {
        assert!(self.current_capacity <= self.chunksize.into());
        let has_partial_chunk = self.current_capacity < self.chunksize.into();
        if self.n_chunks == 0 || (self.n_chunks == 1 && !has_partial_chunk) {
            (1, self.hasher_chunk.finalize())
        } else {
            if has_partial_chunk {
                self.n_chunks += 1;
                self.hasher_whole.update(self.hasher_chunk.finalize());
            }
            (self.n_chunks, self.hasher_whole.finalize())
        }
    }
}

impl io::Write for EtagHasher {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.update(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
