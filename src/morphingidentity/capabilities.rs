#[repr(u32)]
#[cfg_attr(rustfmt, rustfmt_skip)]
pub enum CapType {
    AddCap          = 0b0001u32,
    RemoveCap       = 0b0010u32,
    NonRemovableCap = 0b0100u32,
    SelfUpdateCap   = 0b1000u32,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Capabilities(pub u32);

impl Capabilities {
    pub fn is_permanent(&self) -> bool {
        self.0 & DeviceType::PermanentDevice as u32
            == DeviceType::PermanentDevice as u32
    }
    pub fn is_temporary(&self) -> bool {
        self.0 == DeviceType::TemporaryDevice as u32
    }
    pub fn can_add(&self) -> bool {
        (self.0 & CapType::AddCap as u32) > 0
    }
    pub fn can_remove(&self) -> bool {
        (self.0 & CapType::RemoveCap as u32) > 0
    }
    pub fn cannot_be_removed(&self) -> bool {
        (self.0 & CapType::NonRemovableCap as u32) > 0
    }
    pub fn can_self_update(&self) -> bool {
        (self.0 & CapType::SelfUpdateCap as u32) > 0
    }
}

#[repr(u32)]
pub enum DeviceType {
    TemporaryDevice = 0u32,
    PermanentDevice = CapType::AddCap as u32
        | CapType::RemoveCap as u32
        | CapType::SelfUpdateCap as u32,
}
