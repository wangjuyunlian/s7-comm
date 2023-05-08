use crate::packet::{ConnectComm, CoptFrame, DtData, PduType};
use anyhow::{bail, Error};
use bytes::{Buf, BufMut, BytesMut};
use std::fmt::Debug;
use tokio_util::codec::{Decoder, Encoder};

pub mod packet;

pub struct CoptEncoder<E>(pub E);
pub struct CoptDecoder<D>(pub D);

impl<F: Debug + Eq + PartialEq, E: Encoder<F, Error = Error>> Encoder<CoptFrame<F>>
    for CoptEncoder<E>
// where
//     <E as Encoder<F>>::Error: Into<Error> + Send + Sync + 'static,
{
    type Error = Error;

    fn encode(&mut self, item: CoptFrame<F>, dst: &mut BytesMut) -> Result<(), Self::Error> {
        dst.put_u8(item.length());
        match item.pdu_type {
            PduType::ConnectRequest(conn) => {
                dst.put_u8(0x0e);
                conn.encode(dst);
                Ok(())
            }
            PduType::ConnectConfirm(conn) => {
                dst.put_u8(0x0d);
                conn.encode(dst);
                Ok(())
            }
            PduType::DtData(conn) => {
                dst.put_u8(0x0f);
                let merge = conn.tpdu_number >> 1 & if conn.last_data_unit { 0b1000000 } else { 0 };
                dst.put_u8(merge);
                Ok(self.0.encode(conn.payload, dst)?)
            }
        }
    }
}

impl<F: Debug + Eq + PartialEq, D: Decoder<Item = F, Error = Error>> Decoder for CoptDecoder<D>
// where
//     <D as Decoder>::Error: Into<Error> + std::error::Error + Send + Sync + 'static,
{
    type Item = CoptFrame<F>;
    type Error = Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        let (Some(length), Some(pdu_type)) = (src.get(0), src.get(1)) else {
            return Ok(None)
        };
        let length = *length as usize + 1;
        if src.len() < length || length < 2 {
            return Ok(None);
        };
        match *pdu_type {
            // 0x0e?
            0xe0 => {
                let mut src = src.split_to(length).split_off(2);
                Ok(Some(CoptFrame {
                    pdu_type: PduType::ConnectRequest(ConnectComm::decode(&mut src)?),
                }))
            }
            0xd0 => {
                let mut src = src.split_to(length).split_off(2);
                Ok(Some(CoptFrame {
                    pdu_type: PduType::ConnectConfirm(ConnectComm::decode(&mut src)?),
                }))
            }
            0xf0 => {
                let mut sub_src = src.clone().split_off(length);
                let pre_length = sub_src.len();
                let Some(f) = self.0.decode(&mut sub_src)? else {
                    bail!("decode fail")
                };
                let sub_length = pre_length - sub_src.len();
                let mut src = src.split_to(length + sub_length).split_off(2);
                let merge = src.get_u8();
                let tpdu_number = merge & 0b0111_1111;
                let last_data_unit = merge & 0b1000_0000 > 0;
                Ok(Some(CoptFrame {
                    pdu_type: PduType::DtData(DtData {
                        tpdu_number,
                        last_data_unit,
                        payload: f,
                    }),
                }))
            }
            _ => {
                bail!("not support pdu type: {}", pdu_type);
            }
        }
    }
}
