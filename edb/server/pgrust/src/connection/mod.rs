use std::collections::HashMap;

use crate::auth::{self};
mod conn;
pub mod dsn;
mod openssl;
pub mod params;
mod raw_conn;
pub(crate) mod state_machine;
mod stream;
pub mod tokio;

pub use conn::Client;
pub use dsn::parse_postgres_dsn_env;
pub use raw_conn::connect_raw_ssl;
pub use state_machine::{Authentication, ConnectionSslRequirement};

macro_rules! __invalid_state {
    ($error:literal) => {{
        eprintln!(
            "Invalid connection state: {}\n{}",
            $error,
            ::std::backtrace::Backtrace::capture()
        );
        #[allow(deprecated)]
        $crate::connection::ConnectionError::__InvalidState
    }};
}
pub(crate) use __invalid_state as invalid_state;

#[derive(Debug, thiserror::Error)]
pub enum ConnectionError {
    /// Invalid state error, suggesting a logic error in code rather than a server or client failure.
    /// Use the `invalid_state!` macro instead which will print a backtrace.
    #[error("Invalid state")]
    #[deprecated = "Use invalid_state!"]
    __InvalidState,

    /// Error returned by the server.
    #[error("Server error: {code}: {message}")]
    ServerError {
        code: String,
        message: String,
        extra: HashMap<ServerErrorField, String>,
    },

    /// The server sent something we didn't expect
    #[error("Unexpected server response: {0}")]
    UnexpectedServerResponse(String),

    /// Error related to SCRAM authentication.
    #[error("SCRAM: {0}")]
    Scram(#[from] auth::SCRAMError),

    /// I/O error encountered during connection operations.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// UTF-8 decoding error.
    #[error("UTF8 error: {0}")]
    Utf8Error(#[from] std::str::Utf8Error),

    /// SSL-related error.
    #[error("SSL error: {0}")]
    SslError(#[from] SslError),
}

#[derive(Debug, thiserror::Error)]
pub enum SslError {
    #[error("SSL is not supported by this client transport")]
    SslUnsupportedByClient,
    #[error("SSL was required by the client, but not offered by server")]
    SslRequiredByClient,
    #[error("OpenSSL error: {0}")]
    OpenSslError(#[from] ::openssl::ssl::Error),
    #[error("OpenSSL error: {0}")]
    OpenSslErrorStack(#[from] ::openssl::error::ErrorStack),
}

#[derive(Clone, Default, derive_more::Debug)]
pub struct Credentials {
    pub username: String,
    #[debug(skip)]
    pub password: String,
    pub database: String,
}

/// Enum representing the field types in ErrorResponse and NoticeResponse messages.
///
/// See https://www.postgresql.org/docs/current/protocol-error-fields.html
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, derive_more::TryFrom)]
#[try_from(repr)]
pub enum ServerErrorField {
    /// Severity: ERROR, FATAL, PANIC, WARNING, NOTICE, DEBUG, INFO, or LOG
    Severity = b'S',
    /// Severity (non-localized): ERROR, FATAL, PANIC, WARNING, NOTICE, DEBUG, INFO, or LOG
    SeverityNonLocalized = b'V',
    /// SQLSTATE code for the error
    Code = b'C',
    /// Primary human-readable error message
    Message = b'M',
    /// Optional secondary error message with more detail
    Detail = b'D',
    /// Optional suggestion on how to resolve the problem
    Hint = b'H',
    /// Error cursor position as an index into the original query string
    Position = b'P',
    /// Internal position for internally generated commands
    InternalPosition = b'p',
    /// Text of a failed internally-generated command
    InternalQuery = b'q',
    /// Context in which the error occurred (e.g., call stack traceback)
    Where = b'W',
    /// Schema name associated with the error
    SchemaName = b's',
    /// Table name associated with the error
    TableName = b't',
    /// Column name associated with the error
    ColumnName = b'c',
    /// Data type name associated with the error
    DataTypeName = b'd',
    /// Constraint name associated with the error
    ConstraintName = b'n',
    /// Source-code file name where the error was reported
    File = b'F',
    /// Source-code line number where the error was reported
    Line = b'L',
    /// Source-code routine name reporting the error
    Routine = b'R',
}
