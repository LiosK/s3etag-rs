use std::num::{NonZeroU64, NonZeroUsize};
use std::{error, fs, io, path, process};

#[cfg(unix)]
use std::os::unix::ffi::OsStrExt as _;

use s3etag::{ETag, ETagHasher, ETagHasherMulti};

fn main() -> process::ExitCode {
    const PROG: &str = env!("CARGO_PKG_NAME");
    const THRESHOLD_HELP: &str =
        "multipart_threshold used for upload in bytes or with a size suffix KB, MB, GB, or TB";
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
            clap::Arg::new("threshold")
                .long("threshold")
                .value_name("SIZE")
                .value_parser(parse_threshold)
                .env("S3ETAG_THRESHOLD")
                .default_value("8MB")
                .help(THRESHOLD_HELP),
        )
        .arg(
            clap::Arg::new("chunksize")
                .long("chunksize")
                .value_name("SIZE")
                .value_parser(parse_chunksize)
                .env("S3ETAG_CHUNKSIZE")
                .default_value("8MB")
                .help(CHUNKSIZE_HELP),
        )
        .get_matches();

    let mut exit_code = process::ExitCode::SUCCESS;
    let mut writer = io::LineWriter::new(io::stdout().lock());
    let mut buffer = vec![0u8; 64 * 1024].into_boxed_slice();

    let config = Config {
        threshold: *matches.get_one::<NonZeroU64>("threshold").unwrap(),
        chunksize: *matches.get_one::<NonZeroUsize>("chunksize").unwrap(),
    };

    let mut files = matches
        .get_many::<path::PathBuf>("files")
        .unwrap()
        .fuse()
        .map(|filename| (open_and_fadvise_seq(filename), filename));

    let mut next = files.next();
    while let Some((result_file, filename)) = next {
        // announce the next file before processing the current one
        next = files.next();

        if let Err(e) = process_file(result_file, filename, &config, &mut writer, &mut buffer) {
            exit_code = process::ExitCode::FAILURE;
            eprintln!("error: {}: {}", filename.display(), e);
        }
    }

    exit_code
}

/// Parses the threshold argument.
fn parse_threshold(s: &str) -> Result<NonZeroU64, Box<dyn error::Error + Sync + Send>> {
    let (num, unit) = match s.find(|c: char| !c.is_ascii_digit()) {
        Some(0) => return Err("cannot parse integer".into()),
        None => (s, Ok(1u64)),
        Some(pos) => (
            &s[..pos],
            match &s[pos..] {
                "KB" => Ok(1 << 10),
                "MB" => Ok(1 << 20),
                "GB" => Ok(1 << 30),
                "TB" => Ok(1 << 40),
                _ => Err("unknown size suffix"),
            },
        ),
    };
    num.parse::<NonZeroU64>()?
        .checked_mul(unit?.try_into()?)
        .ok_or_else(|| "too large threshold".into())
}

/// Parses the chunksize argument.
fn parse_chunksize(s: &str) -> Result<NonZeroUsize, Box<dyn error::Error + Sync + Send>> {
    let (num, unit) = match s.find(|c: char| !c.is_ascii_digit()) {
        Some(0) => return Err("cannot parse integer".into()),
        None => (s, Ok(1usize)),
        Some(pos) => (
            &s[..pos],
            match &s[pos..] {
                "KB" => Ok(1 << 10),
                "MB" => Ok(1 << 20),
                "GB" => Ok(1 << 30),
                "TB" => Ok(1 << 40),
                _ => Err("unknown size suffix"),
            },
        ),
    };
    num.parse::<NonZeroUsize>()?
        .checked_mul(unit?.try_into()?)
        .ok_or_else(|| "too large chunksize".into())
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

#[derive(Debug)]
struct Config {
    threshold: NonZeroU64,
    chunksize: NonZeroUsize,
}

/// Computes and prints the ETag for a file.
fn process_file(
    result_file: io::Result<fs::File>,
    filename: &path::Path,
    config: &Config,
    writer: &mut impl io::Write,
    buffer: &mut [u8],
) -> io::Result<()> {
    let etag = {
        fn compute_etag(
            mut hasher: impl ETagHasher,
            file: &mut fs::File,
            buffer: &mut [u8],
        ) -> io::Result<ETag> {
            loop {
                match io::Read::read(file, buffer) {
                    Ok(0) => break Ok(hasher.finalize()),
                    Ok(n) => hasher.update(&buffer[..n]),
                    Err(ref e) if e.kind() == io::ErrorKind::Interrupted => (),
                    Err(e) => break Err(e),
                }
            }
        }

        let mut file = result_file?;
        if file.metadata()?.len() < config.threshold.into() {
            let hasher = Md5::default();
            compute_etag(hasher, &mut file, buffer)
        } else {
            let hasher = ETagHasherMulti::<Md5>::new(config.chunksize);
            compute_etag(hasher, &mut file, buffer)
        }
    }?;

    write!(writer, "{:<39} ", etag)?;

    #[cfg(unix)]
    writer.write_all(filename.as_os_str().as_bytes())?;
    #[cfg(not(unix))]
    write!(writer, "{}", filename.display())?;

    writer.write_all(b"\n")
}

#[cfg(feature = "openssl")]
use s3etag::OpensslMd5 as Md5;

#[cfg(not(feature = "openssl"))]
use md5::Md5; // Either `openssl` or `md-5` must be enabled.
