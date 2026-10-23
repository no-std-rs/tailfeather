#[derive(Default)]
pub struct Timestamp([u8; 12]);
impl Timestamp {
    pub fn next(&mut self) -> wirefeather::Tai64n {
        let millis = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis()
            .min(u64::MAX as u128) as u64;
        crate::logic::next_tai64n(&mut self.0, millis)
    }
}
