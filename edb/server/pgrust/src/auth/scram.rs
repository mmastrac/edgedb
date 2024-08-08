//! # SCRAM (Salted Challenge Response Authentication Mechanism)
//!
//! # Transaction
//!
//! The transaction consists of four steps:
//!
//! 1. **Client's Initial Response**: The client sends its username and initial nonce.
//! 2. **Server's Challenge**: The server responds with a combined nonce, a base64-encoded salt, and an iteration count for the PBKDF2 algorithm.
//! 3. **Client's Proof**: The client sends its proof of possession of the password, along with the combined nonce and base64-encoded channel binding data.
//! 4. **Server's Final Response**: The server sends its verifier, proving successful authentication.
//!
//! This transaction securely authenticates the client to the server without transmitting the actual password.
//!
//! # Parameters
//!
//! The following parameters are used in the SCRAM authentication exchange:
//!
//! * `r=` (nonce): A random string generated by the client and server to ensure the uniqueness of each authentication exchange.
//!   The client initially sends its nonce, and the server responds with a combined nonce (client’s nonce + server’s nonce).
//!
//! * `c=` (channel binding): A base64-encoded representation of the channel binding data.
//!   This parameter is used to bind the authentication to the specific channel over which it is occurring, ensuring the integrity of the communication channel.
//!
//! * `s=` (salt): A base64-encoded salt provided by the server.
//!   The salt is used in conjunction with the client’s password to generate a salted password for enhanced security.
//!
//! * `i=` (iteration count): The number of iterations to apply in the PBKDF2 (Password-Based Key Derivation Function 2) algorithm.
//!   This parameter defines the computational cost of generating the salted password.
//!
//! * `n=` (name): The username of the client.
//!   This parameter is included in the client’s initial response.
//!
//! * `p=` (proof): The client’s proof of possession of the password.
//!   This is a base64-encoded value calculated using the salted password and other SCRAM parameters to prove that the client knows the password without sending it directly.
//!
//! * `v=` (verifier): The server’s verifier, which is used to prove that the server also knows the shared secret.
//!   This parameter is included in the server’s final message to confirm successful authentication.

use base64::{prelude::BASE64_STANDARD, Engine};
use hmac::{Hmac, Mac};
use sha2::{digest::FixedOutput, Digest, Sha256};
use std::borrow::Cow;

const CHANNEL_BINDING_ENCODED: &str = "biws";
const MINIMUM_NONCE_LENGTH: usize = 16;

type HmacSha256 = Hmac<Sha256>;
pub type Sha256Out = [u8; 32];

#[derive(Debug, thiserror::Error)]
pub enum SCRAMError {
    #[error("Invalid encoding")]
    ProtocolError,
}

pub trait ServerEnvironment {
    fn get_password_parameters(&self, username: &str) -> (Cow<'static, str>, usize);
    fn get_salted_password(&self, username: &str) -> Sha256Out;
    fn generate_nonce(&self) -> String;
}

#[derive(Default)]
pub struct ServerTransaction {
    state: ServerState,
}

impl ServerTransaction {
    pub fn success(&self) -> bool {
        matches!(self.state, ServerState::Success)
    }

    pub fn process_message(
        &mut self,
        message: &[u8],
        env: &impl ServerEnvironment,
    ) -> Result<Option<Vec<u8>>, SCRAMError> {
        match &self.state {
            ServerState::Success => Err(SCRAMError::ProtocolError),
            ServerState::Initial => {
                let message = ClientFirstMessage::decode(message)?;
                if message.channel_binding != ChannelBinding::NotSupported("".into()) {
                    return Err(SCRAMError::ProtocolError);
                }
                if message.nonce.len() < MINIMUM_NONCE_LENGTH {
                    return Err(SCRAMError::ProtocolError);
                }
                let (salt, iterations) = env.get_password_parameters(&message.username);
                let mut nonce = message.nonce.to_string();
                nonce += &env.generate_nonce();
                let response = ServerFirstResponse {
                    combined_nonce: nonce.to_string().into(),
                    salt,
                    iterations,
                };
                self.state =
                    ServerState::SentChallenge(message.to_owned_bare(), response.to_owned());
                Ok(Some(response.encode().into_bytes()))
            }
            ServerState::SentChallenge(first_message, first_response) => {
                let message = ClientFinalMessage::decode(message)?;
                if message.combined_nonce != first_response.combined_nonce {
                    return Err(SCRAMError::ProtocolError);
                }
                if message.channel_binding != CHANNEL_BINDING_ENCODED {
                    return Err(SCRAMError::ProtocolError);
                }
                let salted_password = env.get_salted_password(&first_message.username);
                let (client_proof, server_verifier) = generate_proof(
                    first_message.encode().as_bytes(),
                    first_response.encode().as_bytes(),
                    message.channel_binding.as_bytes(),
                    message.combined_nonce.as_bytes(),
                    &salted_password,
                );
                let mut proof = vec![];
                BASE64_STANDARD
                    .decode_vec(message.proof.as_bytes(), &mut proof)
                    .map_err(|_| SCRAMError::ProtocolError)?;
                if proof != client_proof {
                    return Err(SCRAMError::ProtocolError);
                }
                self.state = ServerState::Success;
                let verifier = BASE64_STANDARD.encode(server_verifier).into();
                Ok(Some(ServerFinalResponse { verifier }.encode().into_bytes()))
            }
        }
    }
}

#[derive(Default)]
enum ServerState {
    #[default]
    Initial,
    SentChallenge(ClientFirstMessage<'static>, ServerFirstResponse<'static>),
    Success,
}

pub trait ClientEnvironment {
    fn get_salted_password(&self, salt: &[u8], iterations: usize) -> Sha256Out;
    fn generate_nonce(&self) -> String;
}

pub struct ClientTransaction {
    state: ClientState,
}

impl ClientTransaction {
    pub fn new(username: Cow<'static, str>) -> Self {
        Self {
            state: ClientState::Initial(username),
        }
    }

    pub fn success(&self) -> bool {
        matches!(self.state, ClientState::Success)
    }

    pub fn process_message(
        &mut self,
        message: &[u8],
        env: &impl ClientEnvironment,
    ) -> Result<Option<Vec<u8>>, SCRAMError> {
        match &self.state {
            ClientState::Success => Err(SCRAMError::ProtocolError),
            ClientState::Initial(username) => {
                if !message.is_empty() {
                    return Err(SCRAMError::ProtocolError);
                }
                let nonce = env.generate_nonce().into();
                let message = ClientFirstMessage {
                    channel_binding: ChannelBinding::NotSupported("".into()),
                    username: username.clone(),
                    nonce,
                };
                self.state = ClientState::SentFirst(message.to_owned_bare());
                Ok(Some(message.encode().into_bytes()))
            }
            ClientState::SentFirst(first_message) => {
                let message = ServerFirstResponse::decode(message)?;
                // Ensure the client nonce was concatenated with the server's nonce
                if !message
                    .combined_nonce
                    .starts_with(first_message.nonce.as_ref())
                {
                    return Err(SCRAMError::ProtocolError);
                }
                if message.combined_nonce.len() - first_message.nonce.len() < MINIMUM_NONCE_LENGTH {
                    return Err(SCRAMError::ProtocolError);
                }
                let mut buffer = [0; 1024];
                let salt = decode_salt(&message.salt, &mut buffer)?;
                let salted_password = env.get_salted_password(&salt, message.iterations);
                let (client_proof, server_verifier) = generate_proof(
                    first_message.encode().as_bytes(),
                    message.encode().as_bytes(),
                    CHANNEL_BINDING_ENCODED.as_bytes(),
                    message.combined_nonce.as_bytes(),
                    &salted_password,
                );
                let message = ClientFinalMessage {
                    channel_binding: CHANNEL_BINDING_ENCODED.into(),
                    combined_nonce: message.combined_nonce.to_string().into(),
                    proof: BASE64_STANDARD.encode(client_proof).into(),
                };
                self.state = ClientState::ExpectingVerifier(ServerFinalResponse {
                    verifier: BASE64_STANDARD.encode(server_verifier).into(),
                });
                Ok(Some(message.encode().into_bytes()))
            }
            ClientState::ExpectingVerifier(server_final_response) => {
                let message = ServerFinalResponse::decode(message)?;
                if message.verifier != server_final_response.verifier {
                    return Err(SCRAMError::ProtocolError);
                }
                self.state = ClientState::Success;
                Ok(None)
            }
        }
    }
}

enum ClientState {
    Initial(Cow<'static, str>),
    SentFirst(ClientFirstMessage<'static>),
    ExpectingVerifier(ServerFinalResponse<'static>),
    Success,
}

trait Encode {
    fn encode(&self) -> String;
}

trait Decode<'a> {
    fn decode(buf: &'a [u8]) -> Result<Self, SCRAMError>
    where
        Self: Sized + 'a;
}

fn extract<'a>(input: &'a [u8], prefix: &'static str) -> Result<&'a str, SCRAMError> {
    let bytes = input
        .strip_prefix(prefix.as_bytes())
        .ok_or(SCRAMError::ProtocolError)?;
    std::str::from_utf8(bytes).map_err(|_| SCRAMError::ProtocolError)
}

fn inext<'a>(it: &mut impl Iterator<Item = &'a [u8]>) -> Result<&'a [u8], SCRAMError> {
    it.next().ok_or(SCRAMError::ProtocolError)
}

fn hmac(s: &[u8]) -> HmacSha256 {
    // This is effectively infallible
    HmacSha256::new_from_slice(s).expect("HMAC can take key of any size")
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// `gs2-cbind-flag` from RFC5802.
enum ChannelBinding<'a> {
    /// No channel binding
    NotSpecified,
    /// "n" -> client doesn't support channel binding.
    NotSupported(Cow<'a, str>),
    /// "y" -> client does support channel binding but thinks the server does
    /// not.
    Supported(Cow<'a, str>),
    /// "p" -> client requires channel binding. The selected channel binding
    /// follows "p=".
    Required(Cow<'a, str>, Cow<'a, str>),
}

pub struct ClientFirstMessage<'a> {
    channel_binding: ChannelBinding<'a>,
    username: Cow<'a, str>,
    nonce: Cow<'a, str>,
}

impl ClientFirstMessage<'_> {
    /// Get the bare first message
    pub fn to_owned_bare(&self) -> ClientFirstMessage<'static> {
        ClientFirstMessage {
            channel_binding: ChannelBinding::NotSpecified,
            username: self.username.to_string().into(),
            nonce: self.nonce.to_string().into(),
        }
    }
}

impl Encode for ClientFirstMessage<'_> {
    fn encode(&self) -> String {
        let channel_binding = match self.channel_binding {
            ChannelBinding::NotSpecified => "".to_string(),
            ChannelBinding::NotSupported(ref s) => format!("n,{},", s),
            ChannelBinding::Supported(ref s) => format!("y,{},", s),
            ChannelBinding::Required(ref s, ref t) => format!("p={},{},", t, s),
        };
        format!("{channel_binding}n={},r={}", self.username, self.nonce)
    }
}

impl<'a> Decode<'a> for ClientFirstMessage<'a> {
    fn decode(buf: &'a [u8]) -> Result<Self, SCRAMError> {
        let mut parts = buf.split(|&b| b == b',');

        // Check for channel binding
        let mut next = inext(&mut parts)?;
        let mut channel_binding = ChannelBinding::NotSpecified;
        match (next.len(), next.first()) {
            (_, Some(b'p')) => {
                // p=(cb-name),(authz-id),
                let Some(cb_name) = next.strip_prefix(b"p=") else {
                    return Err(SCRAMError::ProtocolError);
                };
                let cb_name =
                    std::str::from_utf8(cb_name).map_err(|_| SCRAMError::ProtocolError)?;
                let param = inext(&mut parts)?;
                channel_binding = ChannelBinding::Required(
                    Cow::Borrowed(
                        std::str::from_utf8(param).map_err(|_| SCRAMError::ProtocolError)?,
                    ),
                    cb_name.into(),
                );
                next = inext(&mut parts)?;
            }
            (1, Some(b'n')) => {
                let param = inext(&mut parts)?;
                channel_binding = ChannelBinding::NotSupported(Cow::Borrowed(
                    std::str::from_utf8(param).map_err(|_| SCRAMError::ProtocolError)?,
                ));
                next = inext(&mut parts)?;
            }
            (1, Some(b'y')) => {
                let param = inext(&mut parts)?;
                channel_binding = ChannelBinding::Supported(Cow::Borrowed(
                    std::str::from_utf8(param).map_err(|_| SCRAMError::ProtocolError)?,
                ));
                next = inext(&mut parts)?;
            }
            (_, None) => {
                return Err(SCRAMError::ProtocolError);
            }
            _ => {
                // No channel binding specified
            }
        }
        let username = extract(next, "n=")?.into();
        let nonce = extract(inext(&mut parts)?, "r=")?.into();
        Ok(ClientFirstMessage {
            channel_binding,
            username,
            nonce,
        })
    }
}

pub struct ServerFirstResponse<'a> {
    combined_nonce: Cow<'a, str>,
    salt: Cow<'a, str>,
    iterations: usize,
}

impl ServerFirstResponse<'_> {
    pub fn to_owned(&self) -> ServerFirstResponse<'static> {
        ServerFirstResponse {
            combined_nonce: self.combined_nonce.to_string().into(),
            salt: self.salt.to_string().into(),
            iterations: self.iterations,
        }
    }
}

impl Encode for ServerFirstResponse<'_> {
    fn encode(&self) -> String {
        format!(
            "r={},s={},i={}",
            self.combined_nonce, self.salt, self.iterations
        )
    }
}

impl<'a> Decode<'a> for ServerFirstResponse<'a> {
    fn decode(buf: &'a [u8]) -> Result<Self, SCRAMError> {
        let mut parts = buf.split(|&b| b == b',');
        let combined_nonce = extract(inext(&mut parts)?, "r=")?.into();
        let salt = extract(inext(&mut parts)?, "s=")?.into();
        let iterations = extract(inext(&mut parts)?, "i=")?;
        Ok(ServerFirstResponse {
            combined_nonce,
            salt,
            iterations: str::parse(iterations).map_err(|_| SCRAMError::ProtocolError)?,
        })
    }
}

pub struct ClientFinalMessage<'a> {
    channel_binding: Cow<'a, str>,
    combined_nonce: Cow<'a, str>,
    proof: Cow<'a, str>,
}

impl Encode for ClientFinalMessage<'_> {
    fn encode(&self) -> String {
        format!(
            "c={},r={},p={}",
            self.channel_binding, self.combined_nonce, self.proof
        )
    }
}

impl<'a> Decode<'a> for ClientFinalMessage<'a> {
    fn decode(buf: &'a [u8]) -> Result<Self, SCRAMError> {
        let mut parts = buf.split(|&b| b == b',');
        let channel_binding = extract(inext(&mut parts)?, "c=")?.into();
        let combined_nonce = extract(inext(&mut parts)?, "r=")?.into();
        let proof = extract(inext(&mut parts)?, "p=")?.into();
        Ok(ClientFinalMessage {
            channel_binding,
            combined_nonce,
            proof,
        })
    }
}

pub struct ServerFinalResponse<'a> {
    verifier: Cow<'a, str>,
}

impl<'a> Encode for ServerFinalResponse<'a> {
    fn encode(&self) -> String {
        format!("v={}", self.verifier)
    }
}

impl<'a> Decode<'a> for ServerFinalResponse<'a> {
    fn decode(buf: &'a [u8]) -> Result<Self, SCRAMError> {
        let mut parts = buf.split(|&b| b == b',');
        let verifier = extract(inext(&mut parts)?, "v=")?.into();
        Ok(ServerFinalResponse { verifier })
    }
}

pub fn decode_salt<'a>(salt: &str, buffer: &'a mut [u8]) -> Result<Cow<'a, [u8]>, SCRAMError> {
    // The salt needs to be base64 decoded -- full binary must be used
    if let Ok(n) = BASE64_STANDARD.decode_slice(salt, buffer) {
        Ok(Cow::Borrowed(&buffer[..n]))
    } else {
        // In the unlikely case the salt is large -- note that we also fall back to this
        // path for invalid base64 strings!
        let mut buffer = vec![];
        BASE64_STANDARD
            .decode_vec(salt, &mut buffer)
            .map_err(|_| SCRAMError::ProtocolError)?;
        Ok(Cow::Owned(buffer))
    }
}

pub fn generate_salted_password(password: &str, salt: &[u8], iterations: usize) -> Sha256Out {
    // Convert the password to a binary string - UTF8 is safe for SASL
    let p = password.as_bytes();

    // Save the pre-keyed hmac
    let ui_p = hmac(p);

    // The initial signature is the salt with a terminator of a 32-bit string ending in 1
    let mut ui = ui_p.clone();

    ui.update(salt);
    ui.update(&[0, 0, 0, 1]);

    // Grab the initial digest
    let mut last_hash = Default::default();
    ui.finalize_into(&mut last_hash);
    let mut u = last_hash;

    // For X number of iterations, recompute the HMAC signature against the password and the latest iteration of the hash, and XOR it with the previous version
    for _ in 0..(iterations - 1) {
        let mut ui = ui_p.clone();
        ui.update(&last_hash);
        ui.finalize_into(&mut last_hash);
        for i in 0..u.len() {
            u[i] ^= last_hash[i];
        }
    }

    u.as_slice().try_into().unwrap()
}

fn generate_proof(
    first_message_bare: &[u8],
    server_first_message: &[u8],
    channel_binding: &[u8],
    server_nonce: &[u8],
    salted_password: &[u8],
) -> (Sha256Out, Sha256Out) {
    let ui_p = hmac(salted_password);

    let mut ui = ui_p.clone();
    ui.update(b"Server Key");
    let server_key = ui.finalize_fixed();

    let mut ui = ui_p.clone();
    ui.update(b"Client Key");
    let client_key = ui.finalize_fixed();

    let mut hash = Sha256::new();
    hash.update(client_key);
    let stored_key = hash.finalize_fixed();

    let auth_message = [
        (first_message_bare),
        (b","),
        (server_first_message),
        (b",c="),
        (channel_binding),
        (b",r="),
        (server_nonce),
    ];

    let mut client_signature = hmac(&stored_key);
    for chunk in auth_message {
        client_signature.update(chunk);
    }

    let client_signature = client_signature.finalize_fixed();
    let mut client_signature: Sha256Out = client_signature.as_slice().try_into().unwrap();

    for i in 0..client_signature.len() {
        client_signature[i] ^= client_key[i];
    }

    let mut server_proof = hmac(&server_key);
    for chunk in auth_message {
        server_proof.update(chunk);
    }
    let server_proof = server_proof.finalize_fixed().as_slice().try_into().unwrap();

    (client_signature, server_proof)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;
    use rstest::rstest;

    // Define a set of test parameters
    const CLIENT_NONCE: &str = "2XendqvQOa6cl0+Q7Y6UU0gw";
    const SERVER_NONCE: &str = "xWn3mvDeVZwnUtT09vwXoItO";
    const USERNAME: &str = "";
    const PASSWORD: &str = "secret";
    const SALT: &str = "t5YekvL6lgy4RyPnsiyqsg==";
    const ITERATIONS: usize = 4096;
    const CLIENT_PROOF: &[u8] = "p/HmDcOziQQnyF8fbVnJnlvwoLp1kZY4xsI9cCJhzCE=".as_bytes();
    const SERVER_VERIFY: &[u8] = "g/X0codOryF0nCOWh7KkIab23ZFPX99iLzN5Ghn3nNc=".as_bytes();

    #[rstest]
    #[case(
        "1234",
        "1234",
        1,
        hex!("EBE7E5BA4BF5A4D178D3BADAADD4C49A98C72FCFF4FB357DA7090D584990FCAA")
    )]
    #[case(
        "1234",
        "1234",
        2,
        hex!("F9271C334EE6CD7FEE63BBC86FAF951A4ED9E293BDD72AC33663BAE662D31953")
    )]
    #[case(
        "1234",
        "1234",
        4096,
        hex!("4FF8D6443278AB43209DF5A1327949AAC99A5AA23921E5C9199626524776F751")
    )]
    #[case(
        "password",
        "480I9uIaXEU9oB2RRcenOxN/RsOCy0BKJvyRSeuOtQ0cF0hu",
        4096,
        hex!("E118A9AD43C87938659AD736E63F26BA2EBAF079AA351DB44AE29228FB4F7EF0")
    )]
    #[case(
        "secret",
        "480I9uIaXEU9oB2RRcenOxN/RsOCy0BKJvyRSeuOtQ0cF0hu",
        4096,
        hex!("77DFD8E62A4379296C9769F9BA2F77D503C4647DE7919B47D6CF121986981BCC")
    )]
    #[case(
        "secret",
        "t5YekvL6lgy4RyPnsiyqsg==",
        4096,
        hex!("9FB413FE9F1D0C8020400A3D49CFBC47FBFB1251CEA9297630BD025DB2B65171")
    )]
    #[case(
        "😀",
        "t5YekvL6lgy4RyPnsiyqsg==",
        4096,
        hex!("AF490CE1BEA2DDB585DAF9C3842D1528AB091EF6FAB2A92489870523A98835EE")
    )]
    fn test_generate_salted_password(
        #[case] password: &str,
        #[case] salt: &str,
        #[case] iterations: usize,
        #[case] expected_hash: Sha256Out,
    ) {
        let mut buffer = [0; 128];
        let salt = decode_salt(salt, &mut buffer).unwrap();
        let hash = generate_salted_password(password, &salt, iterations);
        assert_eq!(hash, expected_hash);
    }

    #[test]
    fn test_client_proof() {
        let mut buffer = [0; 128];
        let salt = decode_salt(SALT, &mut buffer).unwrap();
        let salted_password = generate_salted_password(PASSWORD, &salt, ITERATIONS);
        let (client, server) = generate_proof(
            format!("n={USERNAME},r={CLIENT_NONCE}").as_bytes(),
            format!("r={CLIENT_NONCE}{SERVER_NONCE},s={SALT},i={ITERATIONS}").as_bytes(),
            CHANNEL_BINDING_ENCODED.as_bytes(),
            format!("{CLIENT_NONCE}{SERVER_NONCE}").as_bytes(),
            &salted_password,
        );
        assert_eq!(
            &client,
            BASE64_STANDARD.decode(CLIENT_PROOF).unwrap().as_slice()
        );
        assert_eq!(
            &server,
            BASE64_STANDARD.decode(SERVER_VERIFY).unwrap().as_slice()
        );
    }

    #[test]
    fn test_client_first_message() {
        let message = ClientFirstMessage::decode(b"n,,n=,r=480I9uIaXEU9oB2RRcenOxN/").unwrap();
        assert_eq!(
            message.channel_binding,
            ChannelBinding::NotSupported(Cow::Borrowed(""))
        );
        assert_eq!(message.username, "");
        assert_eq!(message.nonce, "480I9uIaXEU9oB2RRcenOxN/");
        assert_eq!(
            message.encode(),
            "n,,n=,r=480I9uIaXEU9oB2RRcenOxN/".to_owned()
        );
    }

    #[test]
    fn test_client_first_message_required() {
        let message =
            ClientFirstMessage::decode(b"p=cb-name,,n=,r=480I9uIaXEU9oB2RRcenOxN/").unwrap();
        assert_eq!(
            message.channel_binding,
            ChannelBinding::Required(Cow::Borrowed(""), Cow::Borrowed("cb-name"))
        );
        assert_eq!(message.username, "");
        assert_eq!(message.nonce, "480I9uIaXEU9oB2RRcenOxN/");
        assert_eq!(
            message.encode(),
            "p=cb-name,,n=,r=480I9uIaXEU9oB2RRcenOxN/".to_owned()
        );
    }

    #[test]
    fn test_server_first_response() {
        let message = ServerFirstResponse::decode(
            b"r=480I9uIaXEU9oB2RRcenOxN/RsOCy0BKJvyRSeuOtQ0cF0hu,s=t5YekvL6lgy4RyPnsiyqsg==,i=4096",
        )
        .unwrap();
        assert_eq!(
            message.combined_nonce,
            "480I9uIaXEU9oB2RRcenOxN/RsOCy0BKJvyRSeuOtQ0cF0hu"
        );
        assert_eq!(message.salt, "t5YekvL6lgy4RyPnsiyqsg==");
        assert_eq!(message.iterations, 4096);
        assert_eq!(
            message.encode(),
            "r=480I9uIaXEU9oB2RRcenOxN/RsOCy0BKJvyRSeuOtQ0cF0hu,s=t5YekvL6lgy4RyPnsiyqsg==,i=4096"
                .to_owned()
        );
    }

    #[test]
    fn test_client_final_message() {
        let message = b"c=biws,r=480I9uIaXEU9oB2RRcenOxN/RsOCy0BKJvyRSeuOtQ0cF0hu,p=7Vkz4SfWTNhB3hNdhTucC+3MaGmg3+PrAG3xfuepjP4=";
        let decoded = ClientFinalMessage::decode(message).unwrap();
        assert_eq!(decoded.channel_binding, "biws");
        assert_eq!(
            decoded.combined_nonce,
            "480I9uIaXEU9oB2RRcenOxN/RsOCy0BKJvyRSeuOtQ0cF0hu"
        );
        assert_eq!(
            decoded.proof,
            "7Vkz4SfWTNhB3hNdhTucC+3MaGmg3+PrAG3xfuepjP4="
        );
        let encoded = decoded.encode();
        assert_eq!(encoded, "c=biws,r=480I9uIaXEU9oB2RRcenOxN/RsOCy0BKJvyRSeuOtQ0cF0hu,p=7Vkz4SfWTNhB3hNdhTucC+3MaGmg3+PrAG3xfuepjP4=");
    }

    #[test]
    fn test_server_final_response() {
        let message = b"v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=";
        let decoded: ServerFinalResponse = ServerFinalResponse::decode(message).unwrap();
        assert_eq!(
            decoded.verifier,
            "6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4="
        );
        let encoded = decoded.encode();
        assert_eq!(encoded, "v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=");
    }

    /// Run a SCRAM conversation with a fixed set of parameters
    #[test]
    fn test_transaction() {
        let mut server = ServerTransaction::default();
        let mut client = ClientTransaction::new("username".into());

        struct Env {}
        impl ClientEnvironment for Env {
            fn generate_nonce(&self) -> String {
                "<<<client nonce>>>".into()
            }
            fn get_salted_password(&self, salt: &[u8], iterations: usize) -> Sha256Out {
                generate_salted_password("password", salt, iterations)
            }
        }
        impl ServerEnvironment for Env {
            fn get_salted_password(&self, username: &str) -> Sha256Out {
                assert_eq!(username, "username");
                generate_salted_password("password", b"hello", 4096)
            }
            fn generate_nonce(&self) -> String {
                "<<<server nonce>>>".into()
            }
            fn get_password_parameters(&self, username: &str) -> (Cow<'static, str>, usize) {
                assert_eq!(username, "username");
                (Cow::Borrowed("aGVsbG8="), 4096)
            }
        }
        let env = Env {};

        let message = client.process_message(&[], &env).unwrap().unwrap();
        eprintln!("client: {:?}", String::from_utf8(message.clone()).unwrap());
        let message = server.process_message(&message, &env).unwrap().unwrap();
        eprintln!("server: {:?}", String::from_utf8(message.clone()).unwrap());
        let message = client.process_message(&message, &env).unwrap().unwrap();
        eprintln!("client: {:?}", String::from_utf8(message.clone()).unwrap());
        let message = server.process_message(&message, &env).unwrap().unwrap();
        eprintln!("server: {:?}", String::from_utf8(message.clone()).unwrap());
        assert!(client.process_message(&message, &env).unwrap().is_none());
        assert!(client.success());
        assert!(server.success());
    }
}
