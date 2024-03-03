use std::{fmt, mem, num};

pub trait Md5Hasher: Default {
    type Output: AsRef<[u8]> + Into<[u8; 16]>;

    fn update(&mut self, data: impl AsRef<[u8]>);

    fn finalize(self) -> Self::Output;

    fn finalize_reset(&mut self) -> Self::Output {
        mem::take(self).finalize()
    }
}

#[cfg(feature = "md-5")]
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

#[derive(Debug)]
pub struct EtagHasherMulti<H> {
    chunksize: num::NonZeroUsize,
    n_chunks: usize,
    hasher_whole: H,
    hasher_chunk: H,
    current_capacity: usize,
}

impl<H: Md5Hasher> EtagHasherMulti<H> {
    pub fn new(chunksize: num::NonZeroUsize) -> Self {
        Self {
            chunksize,
            n_chunks: 0,
            hasher_whole: Default::default(),
            hasher_chunk: Default::default(),
            current_capacity: chunksize.into(),
        }
    }

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

    pub fn finalize(mut self) -> Etag<impl AsRef<[u8]>> {
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

#[derive(Debug)]
pub struct Etag<D>(D, usize);

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
