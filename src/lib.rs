//! ARP package parsing and building.
#![no_std]

use core::fmt::{Debug, Display, Formatter};

use byteorder::{ByteOrder, NetworkEndian};

/// Hardware type ethernet
pub const HARDWARE_ETHERNET: u16 = 0x0001;

/// Hardware ethernet address size
pub const HARDWARE_SIZE_ETHERNET: u8 = 6;

/// Protocol type ipv4
pub const PROTOCOL_IPV4: u16 = 0x0800;

/// Protocol ipv4 address size
pub const PROTOCOL_SIZE_IPV4: u8 = 4;

/// Opcode request
pub const OPCODE_REQUEST: u16 = 1;

/// Opcode reply
pub const OPCODE_REPLY: u16 = 2;

/// ARP size
pub const ARP_SIZE: usize = 28;

#[derive(Debug)]
pub enum Error {
    /// Invalid size, too small (at least 28 bytes)
    InvalidSize,

    /// Invalid hardware type, only ethernet supported
    InvalidHardwareType,

    /// Invalid hardware size, only ethernet address size (6 bytes) supported
    InvalidHardwareSize,

    /// Invalid protocol type, only ipv4 supported
    InvalidProtocolType,

    /// Invalid protocol size, only ipv4 address size (4 bytes) supported
    InvalidProtocolSize,

    /// Invalid operation code, only REQUEST (1) or REPLY (2) allowed
    InvalidOpCode,
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:?}", self)
    }
}

/// ARP packet slice
pub struct ARPSlice<'a> {
    data: &'a [u8],
}

impl<'a> ARPSlice<'a> {
    /// Hardware type (only ethernet supported)
    #[inline]
    pub fn hardware_type(&self) -> u16 {
        NetworkEndian::read_u16(&self.data[0..2])
    }

    /// Protocol (only ipv4 supported)
    #[inline]
    pub fn protocol_type(&self) -> u16 {
        NetworkEndian::read_u16(&self.data[2..4])
    }

    /// Hardware address size (ethernet address size, always 6)
    #[inline]
    pub fn hardware_size(&self) -> u8 {
        self.data[4]
    }

    /// Protocol address size (ipv4 address size, always 4)
    #[inline]
    pub fn protocol_size(&self) -> u8 {
        self.data[5]
    }

    /// Operation code, REQUEST or REPLY
    #[inline]
    pub fn op_code(&self) -> u16 {
        NetworkEndian::read_u16(&self.data[6..8])
    }

    /// Sender hardware address (ethernet address)
    #[inline]
    pub fn sender_hardware_addr(&self) -> &[u8] {
        &self.data[8..14]
    }

    /// Sender protocol address (ipv4 address)
    #[inline]
    pub fn sender_protocol_addr(&self) -> &[u8] {
        &self.data[14..18]
    }

    /// Target hardware address (ethernet address)
    #[inline]
    pub fn target_hardware_addr(&self) -> &[u8] {
        &self.data[18..24]
    }

    /// Target protocol address (ipv4 address)
    #[inline]
    pub fn target_protocol_addr(&self) -> &[u8] {
        &self.data[24..28]
    }
}

impl<'a> AsRef<[u8]> for ARPSlice<'a> {
    fn as_ref(&self) -> &[u8] {
        self.data
    }
}

/// Parse a byte buffer (at least 28 bytes) to a ARPSlice
pub fn parse(data: &[u8]) -> Result<ARPSlice, Error> {
    if data.len() < ARP_SIZE {
        return Err(Error::InvalidSize);
    }
    let slice = ARPSlice { data };
    if slice.hardware_type() != HARDWARE_ETHERNET {
        return Err(Error::InvalidHardwareType);
    }
    if slice.protocol_type() != PROTOCOL_IPV4 {
        return Err(Error::InvalidProtocolType);
    }
    if slice.op_code() != OPCODE_REQUEST && slice.op_code() != OPCODE_REPLY {
        return Err(Error::InvalidOpCode);
    }
    if slice.hardware_size() != HARDWARE_SIZE_ETHERNET {
        return Err(Error::InvalidHardwareSize);
    }
    if slice.protocol_size() != PROTOCOL_SIZE_IPV4 {
        return Err(Error::InvalidProtocolSize);
    }
    Ok(slice)
}

/// ARP builder
pub struct ARPSliceBuilder<'a> {
    buf: &'a mut [u8],
}

impl<'a> ARPSliceBuilder<'a> {
    /// Create a new builder with a mutable buffer, initialize it with proper values
    pub fn new(buf: &'a mut [u8]) -> Result<Self, Error> {
        if buf.len() < ARP_SIZE {
            return Err(Error::InvalidSize);
        }
        NetworkEndian::write_u16(&mut buf[0..2], HARDWARE_ETHERNET);
        NetworkEndian::write_u16(&mut buf[2..4], PROTOCOL_IPV4);
        buf[4] = HARDWARE_SIZE_ETHERNET;
        buf[5] = PROTOCOL_SIZE_IPV4;
        NetworkEndian::write_u16(&mut buf[6..8], OPCODE_REQUEST);
        Ok(Self { buf })
    }

    /// Update the operation code
    pub fn op_code(self, op_code: u16) -> Result<Self, Error> {
        if op_code != OPCODE_REQUEST && op_code != OPCODE_REPLY {
            return Err(Error::InvalidOpCode);
        }
        NetworkEndian::write_u16(&mut self.buf[6..8], op_code);
        Ok(Self { buf: self.buf })
    }

    /// Update the sender hardware address
    pub fn sender_hardware_addr(self, ether_addr: &[u8]) -> Result<Self, Error> {
        if ether_addr.len() < HARDWARE_SIZE_ETHERNET as usize {
            return Err(Error::InvalidHardwareSize);
        }
        self.buf[8..14].copy_from_slice(&ether_addr[0..HARDWARE_SIZE_ETHERNET as usize]);
        Ok(Self { buf: self.buf })
    }

    /// Update the sender protocol address
    pub fn sender_protocol_addr(self, ipv4_addr: &[u8]) -> Result<Self, Error> {
        if ipv4_addr.len() < PROTOCOL_SIZE_IPV4 as usize {
            return Err(Error::InvalidProtocolSize);
        }
        self.buf[14..18].copy_from_slice(&ipv4_addr[..4]);
        Ok(Self { buf: self.buf })
    }

    /// Update the target ethernet address
    pub fn target_hardware_addr(self, ether_addr: &[u8]) -> Result<Self, Error> {
        if ether_addr.len() < HARDWARE_SIZE_ETHERNET as usize {
            return Err(Error::InvalidHardwareSize);
        }
        self.buf[18..24].copy_from_slice(&ether_addr[..6]);
        Ok(Self { buf: self.buf })
    }

    /// Update the target protocol address
    pub fn target_protocol_addr(self, ipv4_addr: &[u8]) -> Result<Self, Error> {
        if ipv4_addr.len() < PROTOCOL_SIZE_IPV4 as usize {
            return Err(Error::InvalidProtocolSize);
        }
        self.buf[24..28].copy_from_slice(&ipv4_addr[..4]);
        Ok(Self { buf: self.buf })
    }

    /// Finish
    pub fn build(self) -> &'a mut [u8] {
        self.buf
    }
}

#[cfg(test)]
mod tests {
    use crate::{ARPSliceBuilder, OPCODE_REPLY, OPCODE_REQUEST, parse};

    #[test]
    fn parse_request() {
        let data = [0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x01, 0x38, 0xfc, 0x98, 0x8b, 0x46, 0x10, 0xc0, 0xa8, 0x13, 0x97, 0xf0, 0x18, 0x98, 0x74, 0xe5, 0xd9, 0xc0, 0xa8, 0x12, 0x70];
        let arp_slice = parse(&data);
        assert!(arp_slice.is_ok());

        let arp_slice = arp_slice.unwrap();
        assert_eq!(arp_slice.op_code(), OPCODE_REQUEST);

        assert_eq!(arp_slice.sender_hardware_addr(), &[0x38, 0xfc, 0x98, 0x8b, 0x46, 0x10]);
        assert_eq!(arp_slice.sender_protocol_addr(), &[0xc0, 0xa8, 0x13, 0x97]);
        assert_eq!(arp_slice.target_hardware_addr(), &[0xf0, 0x18, 0x98, 0x74, 0xe5, 0xd9]);
        assert_eq!(arp_slice.target_protocol_addr(), &[0xc0, 0xa8, 0x12, 0x70]);
    }

    #[test]
    fn parse_reply() {
        let data = [0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x02, 0xf0, 0x18, 0x98, 0x74, 0xe5, 0xd9, 0xc0, 0xa8, 0x12, 0x70, 0x38, 0xfc, 0x98, 0x8b, 0x46, 0x10, 0xc0, 0xa8, 0x13, 0x97];
        let arp_slice = parse(&data);
        assert!(arp_slice.is_ok());

        let arp_slice = arp_slice.unwrap();
        assert_eq!(arp_slice.op_code(), OPCODE_REPLY);

        assert_eq!(arp_slice.sender_hardware_addr(), &[0xf0, 0x18, 0x98, 0x74, 0xe5, 0xd9]);
        assert_eq!(arp_slice.sender_protocol_addr(), &[0xc0, 0xa8, 0x12, 0x70]);
        assert_eq!(arp_slice.target_hardware_addr(), &[0x38, 0xfc, 0x98, 0x8b, 0x46, 0x10]);
        assert_eq!(arp_slice.target_protocol_addr(), &[0xc0, 0xa8, 0x13, 0x97]);
    }

    #[test]
    fn build_request() {
        let mut buff = [0; 40];
        let builder = ARPSliceBuilder::new(&mut buff);
        assert!(builder.is_ok());

        let builder = builder.unwrap();
        builder.op_code(OPCODE_REQUEST).unwrap()
            .sender_hardware_addr(&[1, 2, 3, 4, 5, 6]).unwrap()
            .sender_protocol_addr(&[192, 168, 0, 10]).unwrap()
            .target_hardware_addr(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff]).unwrap()
            .target_protocol_addr(&[192, 168, 0, 1]).unwrap();

        let arp_slice = parse(&buff);
        assert!(arp_slice.is_ok());

        let arp_slice = arp_slice.unwrap();
        assert_eq!(arp_slice.op_code(), OPCODE_REQUEST);

        assert_eq!(arp_slice.sender_hardware_addr(), &[1, 2, 3, 4, 5, 6]);
        assert_eq!(arp_slice.sender_protocol_addr(), &[192, 168, 0, 10]);
        assert_eq!(arp_slice.target_hardware_addr(), &[0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
        assert_eq!(arp_slice.target_protocol_addr(), &[192, 168, 0, 1]);
    }
}
