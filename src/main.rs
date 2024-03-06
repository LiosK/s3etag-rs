use std::num::NonZeroUsize;
use std::{error, fs, io, path, process};

#[cfg(unix)]
use std::os::unix::ffi::OsStrExt as _;

use s3etag::{ETagHasherMulti, Md5Hasher};

fn main() -> process::ExitCode {
    const PROG: &str = env!("CARGO_PKG_NAME");
    const CHUNKSIZE_HELP: &str =
        "multipart_chunksize used for upload in bytes or with a size suffix KB, MB, GB, or TB";
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

    let mut files = matches
        .get_many::<path::PathBuf>("files")
        .unwrap()
        .map(|filename| (filename, open_and_fadvise_seq(filename)))
        .fuse();

    let mut next = files.next();
    while let Some((filename, file)) = next {
        next = files.next(); // announce the next file before processing the current one

        let hasher = ETagHasherMulti::<md5_impl::Md5>::new(chunksize);
        if let Err(e) = process_file(filename, file, hasher, &mut writer, buffer.as_deref_mut()) {
            eprintln!("error: {}: {}", filename.display(), e);
            exit_code = process::ExitCode::FAILURE;
        }
    }
    exit_code
}

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

/// Opens a file and calls `posix_fadvise` with `POSIX_FADV_SEQUENTIAL`.
fn open_and_fadvise_seq(filename: &path::Path) -> io::Result<fs::File> {
    let file = fs::File::open(filename)?;

    #[cfg(any(
        linux_android,
        target_os = "emscripten",
        target_os = "fuchsia",
        target_os = "wasi",
        target_env = "uclibc",
        target_os = "freebsd"
    ))]
    if let Err(e) = nix::fcntl::posix_fadvise(
        std::os::fd::AsRawFd::as_raw_fd(file),
        0,
        0,
        nix::fcntl::PosixFadviseAdvice::POSIX_FADV_SEQUENTIAL,
    ) {
        eprintln!(
            "warning: {}: `posix_fadvise(2)` returned error: {}",
            filename.display(),
            e
        );
    }

    Ok(file)
}

/// Computes and prints the ETag for a file.
fn process_file(
    filename: &path::Path,
    file: io::Result<fs::File>,
    mut hasher: ETagHasherMulti<impl Md5Hasher>,
    writer: &mut impl io::Write,
    fread_buffer: Option<&mut [u8]>,
) -> io::Result<()> {
    let mut file = file?;

    match fread_buffer {
        // use mmap if no buffer is supplied
        None => hasher.update(unsafe { memmap2::Mmap::map(&file)? }),
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

#[cfg(feature = "openssl")]
mod md5_impl {
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

#[cfg(not(feature = "openssl"))]
mod md5_impl {
    pub use md5::Md5; // Either `openssl` or `md-5` must be enabled.
}
