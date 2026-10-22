pub fn tai64n() -> wirefeather::Tai64n {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock before epoch");
    let mut out = [0; 12];
    out[..8].copy_from_slice(&(((1u64 << 62) + 10) + now.as_secs()).to_be_bytes());
    out[8..].copy_from_slice(&now.subsec_nanos().to_be_bytes());
    out
}
