use super::{
    server_auth::{ServerAuth, ServerAuthError},
};
use crate::{
    auth::{AuthType, CredentialData},
    connection::ConnectionError,
    errors::{
        PgError, PgErrorConnectionException, PgErrorFeatureNotSupported,
        PgErrorInvalidAuthorizationSpecification, PgServerError, PgServerErrorField,
    },
    handshake::server_auth::{ServerAuthDrive, ServerAuthResponse},
    protocol::{
        edgedb::data::ClientHandshake, match_message, StructBuffer
    },
};
use std::str::Utf8Error;
use tracing::{error, trace, warn};

#[derive(Clone, Copy, Debug)]
pub enum ConnectionStateType {
    Connecting,
    Authenticating,
    Synchronizing,
    Ready,
}

#[derive(Debug)]
pub enum ConnectionDrive<'a> {
    RawMessage(&'a [u8]),
    Message(Result<Message<'a>, ParseError>),
    AuthInfo(AuthType, CredentialData),
    Parameter(String, String),
    Ready(i32, i32),
    Fail(PgError, &'a str),
}

pub trait ConnectionStateSend {
    fn send(&mut self, message: BackendBuilder) -> Result<(), std::io::Error>;
    fn auth(&mut self, user: String, database: String) -> Result<(), std::io::Error>;
    fn params(&mut self) -> Result<(), std::io::Error>;
}

pub trait ConnectionStateUpdate: ConnectionStateSend {
    fn parameter(&mut self, name: &str, value: &str) {}
    fn state_changed(&mut self, state: ConnectionStateType) {}
    fn server_error(&mut self, error: &PgServerError) {}
}

#[derive(Debug)]
pub enum ConnectionEvent<'a> {
    Send(BackendBuilder<'a>),
    Auth(String, String),
    Params,
    Parameter(&'a str, &'a str),
    StateChanged(ConnectionStateType),
    ServerError(&'a PgServerError),
}

impl<F> ConnectionStateSend for F
where
    F: FnMut(ConnectionEvent) -> Result<(), std::io::Error>,
{
    fn send(&mut self, message: BackendBuilder) -> Result<(), std::io::Error> {
        self(ConnectionEvent::Send(message))
    }

    fn auth(&mut self, user: String, database: String) -> Result<(), std::io::Error> {
        self(ConnectionEvent::Auth(user, database))
    }

    fn params(&mut self) -> Result<(), std::io::Error> {
        self(ConnectionEvent::Params)
    }
}

impl<F> ConnectionStateUpdate for F
where
    F: FnMut(ConnectionEvent) -> Result<(), std::io::Error>,
{
    fn parameter(&mut self, name: &str, value: &str) {
        let _ = self(ConnectionEvent::Parameter(name, value));
    }

    fn state_changed(&mut self, state: ConnectionStateType) {
        let _ = self(ConnectionEvent::StateChanged(state));
    }

    fn server_error(&mut self, error: &PgServerError) {
        let _ = self(ConnectionEvent::ServerError(error));
    }
}

#[derive(Debug)]
enum ServerStateImpl {
    Initial,
    AuthInfo(String),
    Authenticating(ServerAuth),
    Synchronizing,
    Ready,
    Error,
}

pub struct ServerState {
    state: ServerStateImpl,
    buffer: StructBuffer<meta::Message>,
}

impl ServerState {
    pub fn new() -> Self {
        Self {
            state: ServerStateImpl::Initial,
            buffer: Default::default(),
        }
    }

    pub fn is_ready(&self) -> bool {
        matches!(self.state, ServerStateImpl::Ready)
    }

    pub fn is_error(&self) -> bool {
        matches!(self.state, ServerStateImpl::Error)
    }

    pub fn is_done(&self) -> bool {
        self.is_ready() || self.is_error()
    }

    pub fn drive(
        &mut self,
        drive: ConnectionDrive,
        update: &mut impl ConnectionStateUpdate,
    ) -> Result<(), ConnectionError> {
        trace!("SERVER DRIVE: {:?} {:?}", self.state, drive);
        let res = match drive {
            ConnectionDrive::RawMessage(raw) => self.buffer.push_fallible(raw, |message| {
                self.state
                    .drive_inner(ConnectionDrive::Message(message), update)
            }),
            drive => self.state.drive_inner(drive, update),
        };

        match res {
            Ok(_) => Ok(()),
            Err(ServerError::IO(e)) => Err(e.into()),
            Err(ServerError::Utf8Error(e)) => Err(e.into()),
            Err(ServerError::Protocol(code)) => {
                self.state = ServerStateImpl::Error;
                send_error(update, code, "Connection error")?;
                Err(PgServerError::new(code, "Connection error", Default::default()).into())
            }
        }
    }
}

impl ServerStateImpl {
    fn drive_inner(
        &mut self,
        drive: ConnectionDrive,
        update: &mut impl ConnectionStateUpdate,
    ) -> Result<(), ServerError> {
        use ServerStateImpl::*;

        match (&mut *self, drive) {
            (Initial, ConnectionDrive::Message(message)) => {
                match_message!(message, Message {
                    (ClientHandshake as handshake) => {
                        let major_ver = handshake.major_ver();
                        let minor_ver = handshake.minor_ver();
                        // TODO: Check version compatibility
                        *self = AuthInfo(String::new()); // No user info in EdgeDB
                        update.auth(String::new(), String::new())?;
                    },
                    unknown => {
                        log_unknown_message(unknown, "Initial")?;
                    }
                });
            }
            (AuthInfo(_), ConnectionDrive::AuthInfo(auth_type, credential_data)) => {
                let mut auth = ServerAuth::new(String::new(), auth_type, credential_data);
                match auth.drive(ServerAuthDrive::Initial) {
                    ServerAuthResponse::Initial(AuthType::ScramSha256, _) => {
                        update.send(BackendBuilder::AuthenticationSASL(
                            builder::AuthenticationSASL {
                                mechanisms: &["SCRAM-SHA-256"],
                            },
                        ))?;
                    }
                    ServerAuthResponse::Complete(..) => {
                        update.send(BackendBuilder::AuthenticationOk(Default::default()))?;
                        *self = Synchronizing;
                        update.params()?;
                        return Ok(());
                    }
                    ServerAuthResponse::Error(e) => return Err(e.into()),
                    _ => return Err(PROTOCOL_ERROR),
                }
                *self = Authenticating(auth);
            }
            (Authenticating(auth), ConnectionDrive::Message(message)) => {
                match_message!(message, Message {
                    (SASLInitialResponse as sasl) if auth.is_initial_message() => {
                        match auth.drive(ServerAuthDrive::Message(AuthType::ScramSha256, sasl.response().as_ref())) {
                            ServerAuthResponse::Continue(final_message) => {
                                update.send(BackendBuilder::AuthenticationSASLContinue(builder::AuthenticationSASLContinue {
                                    data: &final_message,
                                }))?;
                            }
                            ServerAuthResponse::Error(e) => return Err(e.into()),
                            _ => return Err(PROTOCOL_ERROR),
                        }
                    },
                    (SASLResponse as sasl) if !auth.is_initial_message() => {
                        match auth.drive(ServerAuthDrive::Message(AuthType::ScramSha256, sasl.response().as_ref())) {
                            ServerAuthResponse::Complete(data) => {
                                update.send(BackendBuilder::AuthenticationSASLFinal(builder::AuthenticationSASLFinal {
                                    data: &data,
                                }))?;
                                update.send(BackendBuilder::AuthenticationOk(Default::default()))?;
                                *self = Synchronizing;
                                update.params()?;
                            }
                            ServerAuthResponse::Error(e) => return Err(e.into()),
                            _ => return Err(PROTOCOL_ERROR),
                        }
                    },
                    unknown => {
                        log_unknown_message(unknown, "Authenticating")?;
                    }
                });
            }
            (Synchronizing, ConnectionDrive::Parameter(name, value)) => {
                update.send(BackendBuilder::ParameterStatus(builder::ParameterStatus {
                    name: &name,
                    value: &value,
                }))?;
            }
            (Synchronizing, ConnectionDrive::Ready(pid, key)) => {
                update.send(BackendBuilder::BackendKeyData(builder::BackendKeyData {
                    pid,
                    key,
                }))?;
                update.send(BackendBuilder::ReadyForQuery(builder::ReadyForQuery {
                    status: b'I',
                }))?;
                *self = Ready;
            }
            (_, ConnectionDrive::Fail(error, _)) => {
                return Err(ServerError::Protocol(error));
            }
            _ => {
                error!("Unexpected drive in state {:?}", self);
                return Err(PROTOCOL_ERROR);
            }
        }

        Ok(())
    }
}

fn log_unknown_message(
    message: Result<Message, ParseError>,
    state: &str,
) -> Result<(), ServerError> {
    match message {
        Ok(message) => {
            warn!(
                "Unexpected message {:?} (length {}) received in {} state",
                message.mtype(),
                message.mlen(),
                state
            );
            Ok(())
        }
        Err(e) => {
            error!("Corrupted message received in {} state {:?}", state, e);
            Err(PROTOCOL_ERROR)
        }
    }
}
