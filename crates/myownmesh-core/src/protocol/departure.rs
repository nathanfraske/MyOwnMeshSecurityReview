//! Authenticated departure correlation metadata.
//!
//! A departure is scoped by the authenticated session carrying it.  The
//! correlation is only a bounded opaque value used to match the one receipt;
//! it is not a device id, session identity, generation, retry token, or
//! durable authority.

use std::fmt;

use serde::{de::Error as DeError, Deserialize, Deserializer, Serialize, Serializer};

/// Maximum UTF-8 byte length of a departure correlation on the wire.
pub const MAX_DEPARTURE_CORRELATION_BYTES: usize = 128;

/// Opaque correlation for one authenticated `Depart`/`DepartObserved` pair.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DepartureCorrelation(String);

impl DepartureCorrelation {
    /// Construct a correlation after applying the hard wire bound.
    pub fn new(value: impl Into<String>) -> Result<Self, DepartureCorrelationError> {
        let value = value.into();
        if value.is_empty() {
            return Err(DepartureCorrelationError::Empty);
        }
        if value.len() > MAX_DEPARTURE_CORRELATION_BYTES {
            return Err(DepartureCorrelationError::TooLong {
                bytes: value.len(),
                max: MAX_DEPARTURE_CORRELATION_BYTES,
            });
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for DepartureCorrelation {
    type Error = DepartureCorrelationError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl AsRef<str> for DepartureCorrelation {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Display for DepartureCorrelation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl Serialize for DepartureCorrelation {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for DepartureCorrelation {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(D::Error::custom)
    }
}

/// A malformed or unbounded departure correlation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DepartureCorrelationError {
    Empty,
    TooLong { bytes: usize, max: usize },
}

impl fmt::Display for DepartureCorrelationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("departure correlation must not be empty"),
            Self::TooLong { bytes, max } => {
                write!(
                    f,
                    "departure correlation is {bytes} bytes; maximum is {max}"
                )
            }
        }
    }
}

impl std::error::Error for DepartureCorrelationError {}
