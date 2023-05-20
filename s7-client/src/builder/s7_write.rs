use crate::{codec::S7Encoder, error::*};
use bytes::BytesMut;
use copt::CoptFrame;
use s7_comm::{
    DataItemVal, ItemRequest, ReturnCode
};
use tokio_util::codec::Encoder;
use tpkt::TpktFrame;

#[derive(Default)]
pub struct S7WriteBuilder {
    pdu_ref: u16,
    items:   Vec<(ItemRequest, DataItemVal)>
}
impl S7WriteBuilder {
    pub fn pdu_ref(
        mut self,
        pdu_ref: u16
    ) -> Self {
        self.pdu_ref = pdu_ref;
        self
    }

    fn add_item(
        mut self,
        item: (ItemRequest, DataItemVal)
    ) -> Self {
        self.items.push(item);
        self
    }

    // todo 增加其他类型。应该也可以再抽象
    pub fn write_db_bytes(
        self,
        db_number: u16,
        byte_addr: u16,
        data: &[u8]
    ) -> Self {
        let req = ItemRequest::init_db_byte(
            db_number,
            byte_addr,
            0,
            data.len() as u16
        );
        let data_val =
            DataItemVal::init_with_bytes(
                ReturnCode::Reserved,
                data
            );
        self.add_item((req, data_val))
    }

    pub fn write_db_bit(
        self,
        db_number: u16,
        byte_addr: u16,
        bit_addr: u8,
        data: bool
    ) -> Self {
        let req = ItemRequest::init_db_bit(
            db_number, byte_addr, bit_addr, 1
        );
        let data_val = DataItemVal::init_with_bit(
            ReturnCode::Reserved,
            data
        );
        self.add_item((req, data_val))
    }

    pub fn build(self) -> Result<BytesMut> {
        let mut write_builder =
            s7_comm::Frame::job_write_var(
                self.pdu_ref
            );

        for item in self.items {
            write_builder =
                write_builder.add_item(item);
        }
        let frame = TpktFrame::new(
            CoptFrame::builder_of_dt_data(
                write_builder.build()
            )
            .build(0, true)
        );
        let mut dst = BytesMut::new();
        let mut encoder = S7Encoder::default();
        encoder.encode(frame, &mut dst)?;
        Ok(dst)
    }
}
