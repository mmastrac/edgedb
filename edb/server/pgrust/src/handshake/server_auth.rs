use crate::{
    auth::{ServerTransaction, StoredHash, StoredKey},
    handshake::AuthType,
};
use rand::Rng;

#[derive(Debug, Clone)]
pub struct ServerCredentials {
    pub auth_type: AuthType,
    pub credential_data: CredentialData,
}

#[derive(Debug, Clone)]
pub enum CredentialData {
    Trust,
    Deny,
    Plain(String),
    Md5(StoredHash),
    Scram(StoredKey),
}

#[derive(Debug)]
pub enum ServerAuthResponse {
    Initial(AuthType, Vec<u8>),
    Continue(Vec<u8>),
    Complete,
    Error(ServerAuthError),
}

#[derive(Debug)]
pub enum ServerAuthError {
    InvalidAuthorizationSpecification,
    InvalidPassword,
    InvalidSaslMessage,
    UnsupportedAuthType,
}

#[derive(Debug)]
enum ServerAuthState {
    Initial,
    Password(CredentialData),
    MD5([u8; 4], StoredHash),
    SASL(ServerTransaction, StoredKey),
}

pub struct ServerAuth {
    state: ServerAuthState,
    username: String,
    auth_type: AuthType,
    credential_data: CredentialData,
}

impl ServerAuth {
    pub fn new(username: String, auth_type: AuthType, credential_data: CredentialData) -> Self {
        Self {
            state: ServerAuthState::Initial,
            username,
            auth_type,
            credential_data,
        }
    }

    pub fn drive(&mut self, input: &[u8]) -> ServerAuthResponse {
        match &mut self.state {
            ServerAuthState::Initial => self.handle_initial(),
            ServerAuthState::Password(data) => {
                let client_password = input;
                let success = match data {
                    CredentialData::Deny => false,
                    CredentialData::Trust => true,
                    CredentialData::Plain(password) => client_password == password.as_bytes(),
                    CredentialData::Md5(md5) => {
                        let md5_1 = StoredHash::generate(client_password, &self.username);
                        md5_1 == *md5
                    }
                    CredentialData::Scram(scram) => {
                        let key = StoredKey::generate(client_password, &scram.salt, scram.iterations);
                        key.stored_key == scram.stored_key
                    }
                };
                if success {
                    ServerAuthResponse::Complete
                } else {
                    ServerAuthResponse::Error(ServerAuthError::InvalidPassword)
                }
            },
            ServerAuthState::MD5(salt, hash) => {
                if hash.matches(input, *salt) {
                    ServerAuthResponse::Complete
                } else {
                    ServerAuthResponse::Error(ServerAuthError::InvalidPassword)
                }
            },
            ServerAuthState::SASL(tx, data) => {
                match tx.process_message(input, data) {
                    Ok(Some(final_message)) => {
                        if tx.initial() {
                            ServerAuthResponse::Continue(final_message)
                        } else {
                            ServerAuthResponse::Complete
                        }
                    }
                    Ok(None) => ServerAuthResponse::Error(ServerAuthError::InvalidPassword),
                    Err(_) => ServerAuthResponse::Error(ServerAuthError::InvalidSaslMessage),
                }
            },
        }
    }

    fn handle_initial(&mut self) -> ServerAuthResponse {
        match self.auth_type {
            AuthType::Deny => ServerAuthResponse::Error(ServerAuthError::InvalidAuthorizationSpecification),
            AuthType::Trust => ServerAuthResponse::Complete,
            AuthType::Plain => {
                self.state = ServerAuthState::Password(self.credential_data.clone());
                ServerAuthResponse::Initial(AuthType::Plain, Vec::new())
            }
            AuthType::Md5 => {
                let salt: [u8; 4] = rand::random();
                self.state = ServerAuthState::MD5(
                    salt,
                    match &self.credential_data {
                        CredentialData::Md5(hash) => hash.clone(),
                        CredentialData::Plain(password) => {
                            StoredHash::generate(password.as_bytes(), &self.username)
                        }
                        _ => StoredHash::generate(b"", &self.username),
                    },
                );
                ServerAuthResponse::Initial(AuthType::Md5, salt.to_vec())
            }
            AuthType::ScramSha256 => {
                let salt: [u8; 32] = rand::random();
                let scram = match &self.credential_data {
                    CredentialData::Scram(scram) => scram.clone(),
                    CredentialData::Plain(password) => {
                        StoredKey::generate(password.as_bytes(), &salt, 4096)
                    }
                    _ => StoredKey::generate(b"", &salt, 4096),
                };
                let tx = ServerTransaction::default();
                self.state = ServerAuthState::SASL(tx, scram);
                ServerAuthResponse::Initial(AuthType::ScramSha256, Vec::new())
            }
        }
    }

    fn handle_password(&mut self, input: &[u8], data: &CredentialData) -> ServerAuthResponse {
        let client_password = input;
        let success = match data {
            CredentialData::Deny => false,
            CredentialData::Trust => true,
            CredentialData::Plain(password) => client_password == password.as_bytes(),
            CredentialData::Md5(md5) => {
                let md5_1 = StoredHash::generate(client_password, &self.username);
                md5_1 == *md5
            }
            CredentialData::Scram(scram) => {
                let key = StoredKey::generate(client_password, &scram.salt, scram.iterations);
                key.stored_key == scram.stored_key
            }
        };
        if success {
            ServerAuthResponse::Complete
        } else {
            ServerAuthResponse::Error(ServerAuthError::InvalidPassword)
        }
    }

    fn handle_md5(&mut self, input: &[u8], salt: &[u8; 4], md5: &StoredHash) -> ServerAuthResponse {
        if md5.matches(input, *salt) {
            ServerAuthResponse::Complete
        } else {
            ServerAuthResponse::Error(ServerAuthError::InvalidPassword)
        }
    }

    fn handle_sasl(&mut self, input: &[u8], tx: &mut ServerTransaction, data: &StoredKey) -> ServerAuthResponse {
        match tx.process_message(input, data) {
            Ok(Some(final_message)) => {
                if tx.initial() {
                    ServerAuthResponse::Continue(final_message)
                } else {
                    ServerAuthResponse::Complete
                }
            }
            Ok(None) => ServerAuthResponse::Error(ServerAuthError::InvalidPassword),
            Err(_) => ServerAuthResponse::Error(ServerAuthError::InvalidSaslMessage),
        }
    }
}
