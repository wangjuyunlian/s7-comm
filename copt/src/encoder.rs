use bytes::{BufMut, BytesMut};
use std::fmt::Debug;
use tokio_util::codec::Encoder;

use crate::error::*;
use crate::packet::{CoptFrame, PduType};

#[derive(Default)]
pub struct CoptEncoder<E>(pub E);

impl<F: Debug + Eq + PartialEq, E: Encoder<F>> Encoder<CoptFrame<F>> for CoptEncoder<E>
where
    <E as Encoder<F>>::Error: ToCoptError + Send + Sync + 'static,
{
    type Error = Error;

    fn encode(
        &mut self,
        item: CoptFrame<F>,
        dst: &mut BytesMut,
    ) -> std::result::Result<(), Self::Error> {
        dst.put_u8(item.length());
        match item.pdu_type {
            PduType::ConnectRequest(conn) => {
                dst.put_u8(0xe0);
                conn.encode(dst);
                Ok(())
            }
            PduType::ConnectConfirm(conn) => {
                dst.put_u8(0xd0);
                conn.encode(dst);
                Ok(())
            }
            PduType::DtData(conn) => {
                dst.put_u8(0xf0);
                let merge =
                    conn.tpdu_number >> 1 | if conn.last_data_unit { 0b1000_0000 } else { 0 };
                dst.put_u8(merge);
                Ok(self.0.encode(conn.payload, dst)?)
            }
        }
    }
}
