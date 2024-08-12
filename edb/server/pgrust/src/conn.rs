use crate::{
    auth::{self, generate_salted_password, ClientEnvironment, ClientTransaction, Sha256Out},
    protocol::{
        builder, match_message, messages, AuthenticationMessage, AuthenticationOk,
        AuthenticationSASL, AuthenticationSASLContinue, AuthenticationSASLFinal, Backend,
        BackendKeyData, CommandComplete, DataRow, ErrorResponse, Message, ParameterStatus,
        ReadyForQuery, RowDescription,
    },
};
use base64::Engine;
use rand::Rng;
use std::{
    cell::RefCell,
    task::{ready, Poll},
};
use std::{
    collections::VecDeque,
    future::{poll_fn, Future},
    rc::Rc,
    time::Duration,
};
use tokio::io::ReadBuf;

pub trait Stream: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin {}

impl<T> Stream for T where T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin {}

#[derive(Debug, thiserror::Error)]
pub enum PGError {
    #[error("Invalid state")]
    InvalidState,
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("SCRAM: {0}")]
    Scram(#[from] auth::SCRAMError),
}

pub struct Client<S: Stream> {
    conn: Rc<PGConn<S>>,
}

impl<S: Stream> Client<S> {
    /// Create a new PostgreSQL client and a background task.
    pub fn new(
        parameters: ConnectionParameters,
        stm: S,
    ) -> (Self, impl Future<Output = Result<(), PGError>>) {
        let conn = Rc::new(PGConn::new(
            stm,
            parameters.username,
            parameters.password,
            parameters.database,
        ));
        let task = conn.clone().task();
        (Self { conn }, task)
    }

    pub async fn ready(&self) -> Result<(), PGError> {
        loop {
            if !self.conn.is_ready() {
                tokio::time::sleep(Duration::from_millis(100)).await;
            } else {
                return Ok(());
            }
        }
    }

    pub fn query(&self, query: &str) -> impl Future<Output = Result<Vec<Vec<String>>, PGError>> {
        self.conn.clone().query(query.to_owned())
    }
}

pub struct ConnectionParameters {
    pub username: String,
    pub password: String,
    pub database: String,
}

struct PGConn<S: Stream> {
    stm: RefCell<S>,
    state: RefCell<ConnState>,
}

#[derive(Clone)]
struct Credentials {
    username: String,
    password: String,
    database: String,
}

struct QueryWaiter {
    tx: tokio::sync::mpsc::UnboundedSender<()>,
}

enum ConnState {
    Connecting(Credentials),
    Scram(ClientTransaction, ClientEnvironmentImpl),
    Connected,
    Ready(VecDeque<QueryWaiter>),
}

struct ClientEnvironmentImpl {
    credentials: Credentials,
}

impl ClientEnvironment for ClientEnvironmentImpl {
    fn generate_nonce(&self) -> String {
        let nonce: [u8; 32] = rand::thread_rng().r#gen();
        base64::engine::general_purpose::STANDARD.encode(nonce)
    }
    fn get_salted_password(&self, salt: &[u8], iterations: usize) -> Sha256Out {
        generate_salted_password(&self.credentials.password, salt, iterations)
    }
}

impl<S: Stream> PGConn<S> {
    pub fn new(stm: S, username: String, password: String, database: String) -> Self {
        Self {
            stm: stm.into(),
            state: ConnState::Connecting(Credentials {
                username,
                password,
                database,
            })
            .into(),
        }
    }

    fn is_ready(&self) -> bool {
        matches!(&*self.state.borrow(), ConnState::Ready(..))
    }

    async fn write(&self, mut buf: &[u8]) -> Result<(), PGError> {
        println!("Write:");
        hexdump::hexdump(buf);
        loop {
            let n = poll_fn(|cx| {
                let mut stm = self.stm.borrow_mut();
                let stm = std::pin::Pin::new(&mut *stm);
                let n = match ready!(stm.poll_write(cx, buf)) {
                    Ok(n) => n,
                    Err(e) => return Poll::Ready(Err(e)),
                };
                Poll::Ready(Ok(n))
            })
            .await?;
            if n == buf.len() {
                break;
            }
            buf = &buf[n..];
        }
        Ok(())
    }

    fn process_message(&self, message: &[u8]) -> Result<Vec<u8>, PGError> {
        let state = &mut *self.state.borrow_mut();
        let mut send = vec![];
        match state {
            ConnState::Connecting(credentials) => {
                match_message!(message, Backend {
                    (AuthenticationOk) => {
                        eprintln!("auth ok");
                        eprintln!("-> Connected");
                        *state = ConnState::Connected;
                    },
                    (AuthenticationSASL as sasl) => {
                        for mech in sasl.mechanisms() {
                            eprintln!("sasl: {:?}", mech);
                        }
                        let credentials = credentials.clone();
                        let mut tx = ClientTransaction::new("".into());
                        let env = ClientEnvironmentImpl { credentials };
                        let Some(initial_message) = tx.process_message(&[], &env)? else {
                            return Err(auth::SCRAMError::ProtocolError.into());
                        };
                        send = builder::SASLInitialResponse {
                            mechanism: "SCRAM-SHA-256",
                            response: &initial_message,
                        }.to_vec();
                        eprintln!("-> Scram");
                        *state = ConnState::Scram(tx, env);
                    },
                    (ErrorResponse as error) => {
                        for field in error.fields() {
                            eprintln!("error: {} {:?}", field.etype(), field.value());
                        }
                    },
                    (Message as message) => {
                        let mlen = message.mlen();
                        eprintln!("Connecting Unknown message: {} (len {mlen})", message.mtype() as char)
                    },
                    unknown => {
                        eprintln!("Unknown message: {unknown:?}");
                    }
                });
            }
            ConnState::Scram(tx, env) => {
                match_message!(message, Backend {
                    (AuthenticationSASLContinue as sasl) => {
                        let Some(message) = tx.process_message(&sasl.data(), env)? else {
                            return Err(auth::SCRAMError::ProtocolError.into());
                        };
                        send = builder::SASLResponse {
                            response: &message,
                        }.to_vec();
                    },
                    (AuthenticationSASLFinal as sasl) => {
                        let None = tx.process_message(&sasl.data(), env)? else {
                            return Err(auth::SCRAMError::ProtocolError.into());
                        };
                    },
                    (AuthenticationOk) => {
                        eprintln!("auth ok");
                        eprintln!("-> Connected");
                        *state = ConnState::Connected;
                    },
                    (AuthenticationMessage as auth) => {
                        eprintln!("SCRAM Unknown auth message: {}", auth.status())
                    },
                    (ErrorResponse as error) => {
                        for field in error.fields() {
                            eprintln!("error: {} {:?}", field.etype(), field.value());
                        }
                    },
                    (Message as message) => {
                        let mlen = message.mlen();
                        eprintln!("SCRAM Unknown message: {} (len {mlen})", message.mtype() as char)
                    },
                    unknown => {
                        eprintln!("Unknown message: {unknown:?}");
                    }
                });
            }
            ConnState::Connected => {
                match_message!(message, Backend {
                    (ParameterStatus as param) => {
                        eprintln!("param: {:?}={:?}", param.name(), param.value());
                    },
                    (BackendKeyData as key_data) => {
                        eprintln!("key={:?} pid={:?}", key_data.key(), key_data.pid());
                    },
                    (ReadyForQuery as ready) => {
                        eprintln!("ready: {:?}", ready.status() as char);
                        eprintln!("-> Ready");
                        *state = ConnState::Ready(Default::default());
                    },
                    (ErrorResponse as error) => {
                        for field in error.fields() {
                            eprintln!("error: {} {:?}", field.etype(), field.value());
                        }
                    },
                    (Message as message) => {
                        let mlen = message.mlen();
                        eprintln!("Connected Unknown message: {} (len {mlen})", message.mtype() as char)
                    },
                    unknown => {
                        eprintln!("Unknown message: {unknown:?}");
                    }
                });
            }
            ConnState::Ready(queue) => {
                match_message!(message, Backend {
                    (RowDescription as row) => {
                        for field in row.fields() {
                            eprintln!("field: {:?}", field.name());
                        }
                    },
                    (DataRow as row) => {
                        for field in row.values() {
                            eprintln!("field: {:?}", field);
                        }
                    },
                    (CommandComplete as complete) => {
                        eprintln!("complete: {:?}", complete.tag());
                    },
                    (ReadyForQuery as ready) => {
                        eprintln!("ready: {:?}", ready.status() as char);
                        queue.pop_front();
                    },
                    unknown => {
                        eprintln!("Unknown message: {unknown:?}");
                    }
                });
            }
        }

        Ok(send)
    }

    pub async fn task(self: Rc<Self>) -> Result<(), PGError> {
        // Only allow connection in the initial state
        let credentials = match &*self.state.borrow() {
            ConnState::Connecting(credentials) => credentials.clone(),
            _ => {
                return Err(PGError::InvalidState);
            }
        };

        let startup = builder::StartupMessage {
            params: &[
                builder::StartupNameValue {
                    name: "user",
                    value: &credentials.username,
                },
                builder::StartupNameValue {
                    name: "database",
                    value: &credentials.database,
                },
            ],
        }
        .to_vec();
        self.write(&startup).await?;

        let mut messages = vec![];

        loop {
            let mut buffer = [0; 1024];
            let n = poll_fn(|cx| {
                let mut stm = self.stm.borrow_mut();
                let stm = std::pin::Pin::new(&mut *stm);
                let mut buf = ReadBuf::new(&mut buffer);
                ready!(stm.poll_read(cx, &mut buf))
                    .map(|_| buf.filled().len())
                    .into()
            })
            .await?;
            println!("Read:");
            hexdump::hexdump(&buffer[..n]);
            messages.extend_from_slice(&buffer[..n]);
            while messages.len() > 5 {
                let message = Message::new(&messages);
                if message.mlen() <= messages.len() + 1 {
                    let n = message.mlen() + 1;
                    let message = self.process_message(&messages[..n])?;
                    messages = messages[n..].to_vec();
                    if !message.is_empty() {
                        self.write(&message).await?;
                    }
                } else {
                    break;
                }
            }

            if n == 0 {
                break;
            }
        }

        Ok(())
    }

    pub async fn query(self: Rc<Self>, query: String) -> Result<Vec<Vec<String>>, PGError> {
        let mut rx = match &mut *self.state.borrow_mut() {
            ConnState::Ready(queue) => {
                let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
                queue.push_back(QueryWaiter { tx });
                rx
            }
            _ => return Err(PGError::InvalidState),
        };

        let message = builder::Query { query: &query }.to_vec();
        self.write(&message).await?;

        rx.recv().await;
        Ok(vec![])
    }
}

#[cfg(test)]
mod tests {}
