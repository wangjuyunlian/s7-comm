use std::fmt::Debug;

use bytes::{Buf, BufMut, BytesMut};

use crate::builder::ConnectBuilder;
use crate::error::{Error, Result};
use crate::{DtDataBuilder, Parameter};

#[derive(Debug, Eq, PartialEq)]
pub struct CoptFrame<F: Debug + Eq + PartialEq> {
    pub pdu_type: PduType<F>,
}

impl<F: Debug + Eq + PartialEq> CoptFrame<F> {
    pub fn builder_of_dt_data(payload: F) -> DtDataBuilder<F> {
        DtDataBuilder::new(payload)
    }

    pub fn builder_of_connect() -> ConnectBuilder<F> {
        ConnectBuilder::<F>::default()
    }

    pub fn length(&self) -> u8 {
        self.pdu_type.length()
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum PduType<F: Debug + Eq + PartialEq> {
    /// 0x0e
    ConnectRequest(ConnectComm),
    /// 0x0d
    ConnectConfirm(ConnectComm),
    /// 0x0f
    DtData(DtData<F>),
}

impl<F: Debug + Eq + PartialEq> PduType<F> {
    pub fn length(&self) -> u8 {
        match self {
            PduType::ConnectRequest(conn) => conn.length(),
            PduType::ConnectConfirm(conn) => conn.length(),
            PduType::DtData(_) => 2,
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct DtData<F: Debug + Eq + PartialEq> {
    pub(crate) tpdu_number: u8,
    pub(crate) last_data_unit: bool,
    pub(crate) payload: F,
}

impl<F: Debug + Eq + PartialEq> DtData<F> {
    pub fn tpdu_number(&self) -> u8 {
        self.tpdu_number
    }

    pub fn last_data_unit(&self) -> bool {
        self.last_data_unit
    }

    pub fn payload(self) -> F {
        self.payload
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct ConnectComm {
    pub destination_ref: [u8; 2],
    pub source_ref: [u8; 2],
    pub class: u8,
    pub extended_formats: bool,
    pub no_explicit_flow_control: bool,
    pub parameters: Vec<Parameter>,
}

impl ConnectComm {
    pub fn length(&self) -> u8 {
        6 + self.parameters.iter().fold(0, |x, item| x + item.length())
    }

    pub(crate) fn decode(src: &mut BytesMut) -> Result<Self> {
        if src.len() < 5 {
            return Err(Error::Other("data not enough".to_string()));
        }

        let destination_ref = [src.get_u8(), src.get_u8()];
        let source_ref = [src.get_u8(), src.get_u8()];
        let merge = src.get_u8();
        let class = merge >> 4;
        let extended_formats = merge << 6 >> 7 > 0;
        let no_explicit_flow_control = merge & 1 > 0;

        let mut parameters = Vec::new();
        while let Some(parameter) = Parameter::decode(src)? {
            parameters.push(parameter);
        }

        Ok(Self {
            destination_ref,
            source_ref,
            class,
            extended_formats,
            no_explicit_flow_control,
            parameters,
        })
    }

    pub(crate) fn encode(&self, dst: &mut BytesMut) {
        dst.put_slice(self.destination_ref.as_ref());
        dst.put_slice(self.source_ref.as_ref());

        let merge = self.class << 4
            & if self.extended_formats { 2 } else { 0 }
            & if self.no_explicit_flow_control { 1 } else { 0 };

        dst.put_u8(merge);

        self.parameters.iter().for_each(|x| x.encode(dst));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BytesMut;

    #[test]
    fn test_normal_copt_encode_decode() {
        let mut data = BytesMut::new();
        data.extend_from_slice(&[
            0x00, 0x01, 0x00, 0x02, 0x00, 0xc0, 0x01, 0x0a, 0xc1, 0x02, 0x01, 0x00,
        ]);

        let copt_frame = ConnectComm::decode(&mut data).unwrap();
        assert_eq!(copt_frame.length(), 13);
        assert_eq!(copt_frame.destination_ref, [0x00, 0x01]);
        assert_eq!(copt_frame.source_ref, [0x00, 0x02]);
        assert_eq!(copt_frame.class, 0);
        assert_eq!(copt_frame.extended_formats, false);
        assert_eq!(copt_frame.no_explicit_flow_control, false);
        assert_eq!(copt_frame.parameters.len(), 2);

        let parameters = vec![
            Parameter::TpduSize(crate::TpduSize::L1024),
            Parameter::SrcTsap(vec![0x01, 0x00]),
        ];
        assert_eq!(copt_frame.parameters, parameters);
    }

    #[test]
    fn test_unusual_copt_encode_decode() {
        let mut data = BytesMut::new();
        data.extend_from_slice(&[
            0x00, 0x01, 0x00, 0x02, 0x00, 0x02, 0x01, 0x01, 0xc0, 0x01, 0x0a, 0xc1, 0x02, 0x01,
            0x00, 0xc2,
        ]);

        let copt_frame = ConnectComm::decode(&mut data).unwrap();
        assert_eq!(copt_frame.length(), 13);
        assert_eq!(copt_frame.destination_ref, [0x00, 0x01]);
        assert_eq!(copt_frame.source_ref, [0x00, 0x02]);
        assert_eq!(copt_frame.class, 0);
        assert_eq!(copt_frame.extended_formats, false);
        assert_eq!(copt_frame.no_explicit_flow_control, false);
        assert_eq!(copt_frame.parameters.len(), 3);

        let parameters = vec![
            Parameter::Unknown,
            Parameter::TpduSize(crate::TpduSize::L1024),
            Parameter::SrcTsap(vec![0x01, 0x00]),
        ];
        assert_eq!(copt_frame.parameters, parameters);
    }
}
