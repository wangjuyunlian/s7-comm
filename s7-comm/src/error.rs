use copt::error::ToCoptError;
use num_enum::{TryFromPrimitive, TryFromPrimitiveError};
use std::io;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    IoErr(#[from] io::Error),

    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, Error>;

impl<T: TryFromPrimitive> From<TryFromPrimitiveError<T>> for Error {
    fn from(value: TryFromPrimitiveError<T>) -> Self {
        Self::Other(format!("{}", value))
    }
}

impl ToCoptError for Error {
    fn to_err(self) -> copt::error::Error {
        copt::error::Error::Other(self.to_string())
    }
}
