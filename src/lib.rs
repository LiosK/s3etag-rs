#![cfg_attr(docsrs, feature(doc_cfg))]

use std::{fmt, mem, num};

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

/// A hasher state for ETag checksum calculation compatible with [Amazon S3's multipart uploads](https://docs.aws.amazon.com/AmazonS3/latest/userguide/checking-object-integrity.html#large-object-checksums).
#[derive(Debug)]
pub struct ETagHasherMulti<H> {
    chunksize: num::NonZeroUsize,
    n_chunks: usize,
    hasher_whole: H,
    hasher_chunk: H,
    current_capacity: usize,
}

impl<H: Md5Hasher> ETagHasherMulti<H> {
    /// Creates a new hasher configured for a `multipart_chunksize` value.
    pub fn new(chunksize: num::NonZeroUsize) -> Self {
        Self {
            chunksize,
            n_chunks: 0,
            hasher_whole: Default::default(),
            hasher_chunk: Default::default(),
            current_capacity: chunksize.into(),
        }
    }

    /// Updates the internal state by processing the data.
    pub fn update(&mut self, data: impl AsRef<[u8]>) {
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
    pub fn finalize(mut self) -> ETag<impl AsRef<[u8]>> {
        assert!(self.current_capacity <= self.chunksize.into());
        let has_partial_chunk = self.current_capacity < self.chunksize.into();
        if self.n_chunks == 0 || (self.n_chunks == 1 && !has_partial_chunk) {
            ETag(self.hasher_chunk.finalize(), 1)
        } else {
            if has_partial_chunk {
                self.n_chunks += 1;
                self.hasher_whole.update(self.hasher_chunk.finalize());
            }
            ETag(self.hasher_whole.finalize(), self.n_chunks)
        }
    }
}

/// The calculated ETag value type.
#[derive(Debug)]
pub struct ETag<D>(D, usize);

impl<D: AsRef<[u8]>> fmt::Display for ETag<D> {
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
