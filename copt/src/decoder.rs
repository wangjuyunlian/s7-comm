use bytes::{Buf, BytesMut};
use std::fmt::Debug;
use tokio_util::codec::Decoder;

use crate::error::{Error, ToCoptError};
use crate::packet::{ConnectComm, CoptFrame, DtData, PduType};

#[derive(Default)]
pub struct CoptDecoder<D>(pub D);

impl<F: Debug + Eq + PartialEq, D: Decoder<Item = F>> Decoder for CoptDecoder<D>
where
    <D as Decoder>::Error: ToCoptError + Send + Sync + 'static,
{
    type Item = CoptFrame<F>;
    type Error = Error;

    fn decode(
        &mut self,
        src: &mut BytesMut,
    ) -> std::result::Result<Option<Self::Item>, Self::Error> {
        let (Some(length), Some(pdu_type)) = (src.get(0), src.get(1)) else {
            return Ok(None);
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
                    return Err(Error::Other("decode fail".to_string()));
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
                return Err(Error::Other(format!("not support pdu type: {}", pdu_type)));
            }
        }
    }
}
