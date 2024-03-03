use std::mem;

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
