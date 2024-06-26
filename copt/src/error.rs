use num_enum::TryFromPrimitiveError;
use std::io;
use thiserror::Error;
use tpkt::ToTpktError;

use crate::TpduSize;

#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    IoErr(#[from] io::Error),

    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, Error>;

pub trait ToCoptError {
    fn to_err(self) -> Error;
}

impl<T: ToCoptError> From<T> for Error {
    fn from(value: T) -> Self {
        value.to_err()
    }
}

impl ToTpktError for Error {
    fn to_err(self) -> tpkt::Error {
        tpkt::Error::Error(self.to_string())
    }
}

impl From<TryFromPrimitiveError<TpduSize>> for Error {
    fn from(value: TryFromPrimitiveError<TpduSize>) -> Self {
        Self::Other(value.to_string())
    }
}
