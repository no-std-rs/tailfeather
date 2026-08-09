#![no_std]

pub fn make_device() -> wirefeather::Device<1> {
    wirefeather::Device::new([7; 32])
}
