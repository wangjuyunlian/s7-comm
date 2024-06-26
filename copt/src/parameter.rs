use std::fmt::Debug;

use bytes::{Buf, BufMut, BytesMut};
use num_enum::{IntoPrimitive, TryFromPrimitive};

use crate::error::*;

#[derive(Debug, Clone, Copy, Eq, PartialEq, TryFromPrimitive, IntoPrimitive)]
#[repr(u8)]
pub enum TpduSize {
    L8192 = 0b0000_1101,
    L4096 = 0b0000_1100,
    L2048 = 0b0000_1011,
    L1024 = 0b0000_1010,
    L512 = 0b0000_1001,
    L256 = 0b0000_1000,
    L128 = 0b0000_0111,
}

impl TpduSize {
    pub fn pdu_ref(&self) -> u16 {
        match self {
            TpduSize::L8192 => 8192,
            TpduSize::L4096 => 4096,
            TpduSize::L2048 => 2048,
            TpduSize::L1024 => 1024,
            TpduSize::L512 => 512,
            TpduSize::L256 => 256,
            TpduSize::L128 => 128,
        }
    }
}

/// https://datatracker.ietf.org/doc/html/rfc905 13.3.4
#[derive(Debug, Eq, PartialEq)]
pub enum Parameter {
    /// 0xc0
    ///            0000 1101  8192 octets (not
    /// allowed in Class 0)
    //             0000 1100  4096 octets (not
    // allowed in Class 0)             0000
    // 1011  2048 octets             0000
    // 1010  1024 octets             0000
    // 1001   512 octets             0000
    // 1000   256 octets             0000
    // 0111   128 octets
    TpduSize(TpduSize),
    /// Source Reference
    /// 0xc1
    SrcTsap(Vec<u8>),
    /// Destination Reference
    /// 0xc2
    DstTsap(Vec<u8>),
    // unknown, 0x02
    Unknown,
}

impl Parameter {
    pub fn new_dst_tsap(data: Vec<u8>) -> Self {
        Self::DstTsap(data)
    }

    pub fn new_src_tsap(data: Vec<u8>) -> Self {
        Self::SrcTsap(data)
    }

    pub fn new_tpdu_size(size: TpduSize) -> Self {
        Self::TpduSize(size)
    }

    pub fn length(&self) -> u8 {
        match self {
            Parameter::TpduSize(_) => 3u8,
            Parameter::SrcTsap(data) => 2 + data.len() as u8,
            Parameter::DstTsap(data) => 2 + data.len() as u8,
            Parameter::Unknown => 0,
        }
    }

    pub(crate) fn decode(data: &mut BytesMut) -> Result<Option<Self>> {
        // NOTICE: CPU 200 碰到出现 0x02 参数码的机器, 0xc2 参数码在最末尾, 且没有参数数据
        if data.len() == 1 && data[0] == 0xc2 {
            return Ok(None);
        }

        // data is empty, parse done
        if data.len() == 0 {
            return Ok(None);
        }

        let (Some(parameter_code), Some(length)) = (data.get(0), data.get(1)) else {
            return Err(Error::Other(
                "decode parameter header data not enough".to_string(),
            ));
        };

        let parameter_code = *parameter_code;
        let length = (length + 2) as usize;
        if data.len() < length {
            return Err(Error::Other(format!(
                "data.len={} need length={}, data not enough",
                data.len(),
                length
            )));
        }

        let mut data = data.split_to(length).split_off(2);

        match parameter_code {
            0xc0 => {
                let size = data.get_u8();
                Ok(Some(Self::TpduSize(size.try_into()?)))
            }
            0xc1 => Ok(Some(Self::SrcTsap(data.to_vec()))),
            0xc2 => Ok(Some(Self::DstTsap(data.to_vec()))),
            // CPU 200. Unknown parameter type, skip it
            0x02 => Ok(Some(Self::Unknown)),
            _ => {
                return Err(Error::Other(format!(
                    "unknown parameter code: {}",
                    parameter_code
                )));
            }
        }
    }

    pub(crate) fn encode(&self, dst: &mut BytesMut) {
        match self {
            Parameter::TpduSize(data) => {
                dst.put_u8(0xc0);
                dst.put_u8(1u8);
                dst.put_u8(data.clone().into())
            }
            Parameter::SrcTsap(data) => {
                dst.put_u8(0xc1);
                dst.put_u8(data.len() as u8);
                dst.extend_from_slice(data.as_ref())
            }
            Parameter::DstTsap(data) => {
                dst.put_u8(0xc2);
                dst.put_u8(data.len() as u8);
                dst.extend_from_slice(data.as_ref())
            }
            Parameter::Unknown => {
                // do nothing
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BytesMut;

    #[test]
    fn test_decode_unknown0x02_parameter() {
        let mut data = BytesMut::new();
        data.extend_from_slice(&[0x02, 0x01, 0x01]);

        let parameter = Parameter::decode(&mut data).unwrap().unwrap();
        assert_eq!(parameter, Parameter::Unknown);
        assert_eq!(parameter.length(), 0);

        let mut buf = BytesMut::new();
        parameter.encode(&mut buf);
        assert_eq!(buf.len(), 0);
    }

    #[test]
    fn test_encode_unknown0x02_parameter() {
        let parameter = Parameter::Unknown;
        let mut buf = BytesMut::new();
        parameter.encode(&mut buf);
        assert_eq!(buf.len(), 0);
    }

    #[test]
    fn test_decode_unusual_0xc2_only() {
        let mut data = BytesMut::new();
        data.extend_from_slice(&[0xc2]);

        let parameter = Parameter::decode(&mut data).unwrap();
        assert_eq!(parameter, None);
    }

    #[test]
    fn test_encode_decode_tpdu_size() {
        let mut data = BytesMut::new();
        data.extend_from_slice(&[0xc0, 0x01, 0x0a]);

        let parameter = Parameter::decode(&mut data).unwrap().unwrap();
        assert_eq!(parameter, Parameter::TpduSize(TpduSize::L1024));
        assert_eq!(parameter.length(), 3);

        let mut buf = BytesMut::new();
        parameter.encode(&mut buf);
        assert_eq!(buf.as_ref(), &[0xc0, 0x01, 0x0a]);
    }

    #[test]
    fn test_encode_decode_src_tsap() {
        let mut data = BytesMut::new();
        data.extend_from_slice(&[0xc1, 0x02, 0x01, 0x00]);

        let parameter = Parameter::decode(&mut data).unwrap().unwrap();
        assert_eq!(parameter, Parameter::SrcTsap(vec![0x01, 0x00]));
        assert_eq!(parameter.length(), 4);

        let mut buf = BytesMut::new();
        parameter.encode(&mut buf);
        assert_eq!(buf.as_ref(), &[0xc1, 0x02, 0x01, 0x00]);
    }
}
