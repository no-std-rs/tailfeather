#![no_std]

pub fn preface(out: &mut [u8]) -> Result<usize, micro_h2::Error> {
    micro_h2::Connection::new().start(out)
}
