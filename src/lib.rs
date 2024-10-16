use digest::consts::U32;
use digest::{Digest, FixedOutput, FixedOutputReset, Output, OutputSizeUser, Reset, Update};
use digest::core_api::CoreWrapper;
use sha3::{Sha3_256, Sha3_256Core};

struct WeakSha3256 {
    inner_sha3: Sha3_256
}

impl OutputSizeUser for WeakSha3256 { type OutputSize = U32; }

impl Digest for WeakSha3256 {
    fn new() -> Self {
        Self {
            inner_sha3: Sha3_256::new()
        }
    }

    fn new_with_prefix(data: impl AsRef<[u8]>) -> Self {
        let mut data_cloned: Vec<u8> = Vec::from(data.as_ref());
        data_cloned[0] &= 0b0111111;
        Self {
            inner_sha3: Sha3_256::new_with_prefix(data_cloned)
        }
    }

    fn update(&mut self, data: impl AsRef<[u8]>) {
        let mut data_cloned: Vec<u8> = Vec::from(data.as_ref());
        data_cloned[0] &= 0b0111111;
        Digest::update(&mut self.inner_sha3, data_cloned)
    }

    fn chain_update(self, data: impl AsRef<[u8]>) -> Self {
        let mut data_cloned: Vec<u8> = Vec::from(data.as_ref());
        data_cloned[0] &= 0b0111111;
        Self {
            inner_sha3: self.inner_sha3.chain_update(data_cloned)
        }
    }

    fn finalize(self) -> Output<Self> {
        self.inner_sha3.finalize()
    }

    fn finalize_into(self, out: &mut Output<Self>) {
        Digest::finalize_into(self.inner_sha3, out)
    }

    fn finalize_reset(&mut self) -> Output<Self>
    where
        Self: FixedOutputReset
    {
        Digest::finalize_reset(&mut self.inner_sha3)
    }

    fn finalize_into_reset(&mut self, out: &mut Output<Self>)
    where
        Self: FixedOutputReset
    {
        Digest::finalize_into_reset(&mut self.inner_sha3, out)
    }

    fn reset(&mut self)
    where
        Self: Reset
    {
        Digest::reset(&mut self.inner_sha3)
    }

    fn output_size() -> usize {
        <CoreWrapper<Sha3_256Core> as Digest>::output_size()
    }

    fn digest(data: impl AsRef<[u8]>) -> Output<Self> {
        let mut data_cloned: Vec<u8> = Vec::from(data.as_ref());
        data_cloned[0] &= 0b0111111;
        Sha3_256::digest(data_cloned)
    }
}

impl FixedOutput for WeakSha3256 {
    fn finalize_into(self, out: &mut Output<Self>) {
        FixedOutput::finalize_into(self.inner_sha3, out)
    }
}

impl Update for WeakSha3256 {
    fn update(&mut self, data: &[u8]) {
        Update::update(&mut self.inner_sha3, data)
    }
}

impl Reset for WeakSha3256 {
    fn reset(&mut self) {
        Reset::reset(&mut self.inner_sha3)
    }
}

impl FixedOutputReset for WeakSha3256 {
    fn finalize_into_reset(&mut self, out: &mut Output<Self>) {
        FixedOutputReset::finalize_into_reset(&mut self.inner_sha3, out)
    }
}

#[cfg(test)]
mod tests {
    use digest::Digest;
    use sha3::Sha3_256;
    use crate::WeakSha3256;

    #[test]
    fn test_same_hash() {
        let mut weak_sha3_256 = WeakSha3256::new();
        Digest::update(&mut weak_sha3_256, [1, 2]);

        let mut normal_sha3_256 = Sha3_256::new();
        Digest::update(&mut normal_sha3_256, [1, 2]);

        assert_eq!(normal_sha3_256.finalize(), weak_sha3_256.finalize());
    }

    #[test]
    fn test_different_hash() {
        let mut weak_sha3_256 = WeakSha3256::new();
        Digest::update(&mut weak_sha3_256, [130, 2]);

        let mut normal_sha3_256 = Sha3_256::new();
        Digest::update(&mut normal_sha3_256, [130, 2]);

        assert_ne!(normal_sha3_256.finalize(), weak_sha3_256.finalize());
    }
}