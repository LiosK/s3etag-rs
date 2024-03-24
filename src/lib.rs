#![cfg_attr(docsrs, feature(doc_cfg))]

use std::{fmt, mem, num::NonZeroUsize};

use arrayvec::ArrayString;

/// A trait that defines the minimum requirements for an underlying MD5 hasher.
pub trait Md5Hasher: Default {
    type Output: AsRef<[u8]> + Into<[u8; 16]>;

    /// Updates the internal state by processing the data.
    fn update(&mut self, data: impl AsRef<[u8]>);

    /// Returns the result, consuming the hasher.
    fn finalize(self) -> Self::Output;

    /// Returns the result, reseting the hasher to the initial state.
    fn finalize_reset(&mut self) -> Self::Output {
        mem::take(self).finalize()
    }
}

/// A trait for ETag hasher states.
pub trait ETagHasher {
    /// Updates the internal state by processing the data.
    fn update(&mut self, data: impl AsRef<[u8]>);

    /// Returns the result, consuming the hasher.
    fn finalize(self) -> ETag;
}

impl<T: Md5Hasher> ETagHasher for T {
    fn update(&mut self, data: impl AsRef<[u8]>) {
        self.update(data)
    }

    fn finalize(self) -> ETag {
        self.finalize().into().into()
    }
}

/// A hasher state for multipart ETag checksum calculation compatible with [Amazon S3's multipart uploads](https://docs.aws.amazon.com/AmazonS3/latest/userguide/checking-object-integrity.html#large-object-checksums).
#[derive(Debug)]
pub struct ETagHasherMulti<H> {
    chunksize: NonZeroUsize,
    n_chunks: usize,
    hasher_whole: H,
    hasher_chunk: H,
    current_capacity: usize,
}

impl<H: Md5Hasher> ETagHasherMulti<H> {
    /// Creates a new hasher configured for a `multipart_chunksize` value.
    pub fn new(chunksize: NonZeroUsize) -> Self {
        Self {
            chunksize,
            n_chunks: 0,
            hasher_whole: Default::default(),
            hasher_chunk: Default::default(),
            current_capacity: chunksize.into(),
        }
    }
}

impl<H: Md5Hasher> ETagHasher for ETagHasherMulti<H> {
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
        if !buf.is_empty() {
            self.hasher_chunk.update(buf);
            self.current_capacity -= buf.len();
        }
    }

    /// Returns the result, consuming the hasher.
    ///
    /// Note that this method returns a non-multipart ETag if this hasher has not consumed any
    /// byte. This is because awscli does not accept zero multipart_threshold, and thus multipart
    /// uploading is not applicable to an empty file.
    fn finalize(mut self) -> ETag {
        assert!(self.current_capacity <= self.chunksize.into());
        if self.current_capacity < self.chunksize.into() {
            self.n_chunks += 1;
            self.hasher_whole.update(self.hasher_chunk.finalize());
        }
        ETag {
            digest: self.hasher_whole.finalize().into(),
            n_chunks: self.n_chunks.try_into().ok(),
        }
    }
}

/// The calculated ETag value type.
#[derive(Debug)]
pub struct ETag {
    digest: [u8; 16],
    n_chunks: Option<NonZeroUsize>,
}

impl fmt::Display for ETag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use fmt::Write as _;
        let mut buf = ArrayString::<64>::new();
        for e in self.digest {
            write!(buf, "{:02x}", e)?;
        }
        if let Some(n) = self.n_chunks {
            write!(buf, "-{}", n)?;
        }
        fmt::Display::fmt(buf.as_str(), f)
    }
}

impl From<[u8; 16]> for ETag {
    fn from(digest: [u8; 16]) -> Self {
        Self {
            digest,
            n_chunks: None,
        }
    }
}

#[cfg(feature = "md-5")]
#[cfg_attr(docsrs, doc(cfg(feature = "md-5")))]
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

#[cfg(feature = "openssl")]
pub use openssl_bindings::OpensslMd5;

#[cfg(feature = "openssl")]
#[cfg_attr(docsrs, doc(cfg(feature = "openssl")))]
mod openssl_bindings {
    use openssl::{md::Md, md_ctx::MdCtx};

    use super::Md5Hasher;

    /// A wrapper for OpenSSL's `EVP_MD_CTX` object to implement [`Md5Hasher`].
    ///
    /// Note that implemented trait methods of this type may panic if the underlying OpenSSL
    /// functions unexpectedly return an error.
    pub struct OpensslMd5(MdCtx);

    impl Default for OpensslMd5 {
        fn default() -> Self {
            let mut ctx = MdCtx::new().expect("openssl error");
            ctx.digest_init(Md::md5()).expect("openssl error");
            Self(ctx)
        }
    }

    impl Md5Hasher for OpensslMd5 {
        type Output = [u8; 16];

        fn update(&mut self, data: impl AsRef<[u8]>) {
            self.0.digest_update(data.as_ref()).expect("openssl error");
        }

        fn finalize(mut self) -> Self::Output {
            let mut buffer = [0; 16];
            self.0.digest_final(&mut buffer).expect("openssl error");
            buffer
        }

        fn finalize_reset(&mut self) -> Self::Output {
            let mut buffer = [0; 16];
            self.0.digest_final(&mut buffer).expect("openssl error");
            self.0.digest_init(Md::md5()).expect("openssl error");
            buffer
        }
    }
}
