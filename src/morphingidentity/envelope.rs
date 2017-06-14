


const ENVELOPE_VERSION: u8 = 2;

pub struct Envelope<'r> {
    version: u8,
    mac: Mac,
    message: Message<'r>,
    message_enc: Vec<u8>,
}
