use serde_derive::Serialize;
use std::borrow::Cow;
use std::collections::HashMap;
use std::io::ErrorKind;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::Duration;
use thiserror::Error;

#[derive(Error, Debug, PartialEq, Eq)]
#[allow(clippy::enum_variant_names)]
pub enum ParseError {
    #[error(
        "Invalid DSN: scheme is expected to be either \"postgresql\" or \"postgres\", got {0}"
    )]
    InvalidScheme(String),

    #[error("Invalid value for parameter \"{0}\": \"{1}\"")]
    InvalidParameter(String, String),

    #[error("Invalid percent encoding")]
    InvalidPercentEncoding,

    #[error("Invalid port: \"{0}\"")]
    InvalidPort(String),

    #[error("Unexpected number of ports, must be either a single port or the same number as the host count: \"{0}\"")]
    InvalidPortCount(String),

    #[error("Invalid hostname: \"{0}\"")]
    InvalidHostname(String),

    #[error("Invalid query parameter: \"{0}\"")]
    InvalidQueryParameter(String),

    #[error("Invalid TLS version: \"{0}\"")]
    InvalidTLSVersion(String),

    #[error("Could not determine the connection {0}")]
    MissingRequiredParameter(String),

    #[error("URL parse error: {0}")]
    UrlParseError(#[from] url::ParseError),
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub enum HostType {
    Hostname(String),
    IP(IpAddr, Option<String>),
    Path(String),
    Abstract(String),
}

impl std::fmt::Display for HostType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HostType::Hostname(hostname) => write!(f, "{}", hostname),
            HostType::IP(ip, Some(interface)) => write!(f, "{}%{}", ip, interface),
            HostType::IP(ip, None) => {
                write!(f, "{}", ip)
            }
            HostType::Path(path) => write!(f, "{}", path),
            HostType::Abstract(name) => write!(f, "@{}", name),
        }
    }
}

impl HostType {
    pub fn try_from_str(s: &str) -> Result<Self, ParseError> {
        if s.is_empty() {
            return Err(ParseError::InvalidHostname("".to_string()));
        }
        if s.contains('[') || s.contains(']') {
            return Err(ParseError::InvalidHostname(s.to_string()));
        }
        if s.starts_with('/') {
            return Ok(HostType::Path(s.to_string()));
        }
        if s.starts_with('@') {
            return Ok(HostType::Abstract(s[1..].to_string()));
        }
        if s.contains('%') {
            let (ip_str, interface) = s.split_once('%').unwrap();
            if interface.is_empty() {
                return Err(ParseError::InvalidHostname(s.to_string()));
            }
            let ip = ip_str
                .parse::<Ipv6Addr>()
                .map_err(|_| ParseError::InvalidHostname(s.to_string()))?;
            return Ok(HostType::IP(IpAddr::V6(ip), Some(interface.to_string())));
        }
        if let Ok(ip) = s.parse::<IpAddr>() {
            Ok(HostType::IP(ip, None))
        } else {
            if s.contains(':') {
                return Err(ParseError::InvalidHostname(s.to_string()));
            }
            Ok(HostType::Hostname(s.to_string()))
        }
    }

    fn resolve(&self) -> std::io::Result<Vec<HostType>> {
        match self {
            Self::Hostname(host) => {
                use std::net::ToSocketAddrs;
                Ok((host.as_str(), 1)
                    .to_socket_addrs()?
                    .map(|addr| {
                        eprintln!("{addr:?}");
                        match addr {
                            SocketAddr::V4(addr) => HostType::IP(IpAddr::V4(*addr.ip()), None),
                            SocketAddr::V6(addr) => HostType::IP(IpAddr::V6(*addr.ip()), None),
                        }
                    })
                    .collect())
            }
            x => Ok(vec![x.clone()]),
        }
    }
}

impl std::str::FromStr for HostType {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        HostType::try_from_str(s)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct Host(pub HostType, pub u16);

#[derive(Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub enum Password {
    /// The password is unspecified and should be read from the user's default
    /// passfile if it exists.
    #[default]
    Unspecified,
    /// The password was specified.
    Specified(String),
    /// The passfile is specified.
    Passfile(PathBuf),
}

#[derive(Serialize)]
pub enum PasswordWarning {
    NotFile(PathBuf),
    NotExists(PathBuf),
    NotAccessible(PathBuf),
    Permissions(PathBuf, u32),
}

impl std::fmt::Display for PasswordWarning {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PasswordWarning::NotFile(path) => write!(f, "Password file {path:?} is not a plain file"),
            PasswordWarning::NotExists(path) => write!(f, "Password file {path:?} does not exist"),
            PasswordWarning::NotAccessible(path) => write!(f, "Password file {path:?} is not accessible"),
            PasswordWarning::Permissions(path, mode) => write!(f, "Password file {path:?} has group or world access ({mode:o}); permissions should be u=rw (0600) or less"),
        }
    }
}

impl Password {
    pub fn password(&self) -> Option<&str> {
        match self {
            Password::Specified(password) => Some(password),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct ConnectionParameters {
    pub hosts: Vec<Host>,
    pub database: String,
    pub user: String,
    pub password: Password,
    pub connect_timeout: Option<Duration>,
    pub server_settings: HashMap<String, String>,
    pub ssl: Ssl,
}

impl Into<HashMap<String, String>> for ConnectionParameters {
    fn into(self) -> HashMap<String, String> {
        let mut map = HashMap::new();

        if !self.hosts.is_empty() {
            let hosts: Vec<String> = self.hosts.iter().map(|h| h.0.to_string()).collect();
            map.insert("host".to_string(), hosts.join(","));

            let ports: Vec<String> = self.hosts.iter().map(|h| h.1.to_string()).collect();
            map.insert("port".to_string(), ports.join(","));
        }

        map.insert("dbname".to_string(), self.database);
        map.insert("user".to_string(), self.user);

        match self.password {
            Password::Specified(ref pw) => {
                map.insert("password".to_string(), pw.to_string());
            }
            Password::Passfile(ref path) => {
                map.insert("passfile".to_string(), path.to_string_lossy().into_owned());
            }
            _ => {}
        }

        if let Some(timeout) = self.connect_timeout {
            map.insert("connect_timeout".to_string(), timeout.as_secs().to_string());
        }

        match self.ssl {
            Ssl::Disable => {
                map.insert("sslmode".to_string(), "disable".to_string());
            }
            Ssl::Enable(mode, ref params) => {
                map.insert("sslmode".to_string(), mode.to_string());
                if let Some(ref cert) = params.cert {
                    map.insert("sslcert".to_string(), cert.to_string_lossy().into_owned());
                }
                if let Some(ref key) = params.key {
                    map.insert("sslkey".to_string(), key.to_string_lossy().into_owned());
                }
                if let Some(ref password) = params.password {
                    map.insert("sslpassword".to_string(), password.to_string());
                }
                if let Some(ref rootcert) = params.rootcert {
                    map.insert(
                        "sslrootcert".to_string(),
                        rootcert.to_string_lossy().into_owned(),
                    );
                }
                if let Some(ref crl) = params.crl {
                    map.insert("sslcrl".to_string(), crl.to_string_lossy().into_owned());
                }
            }
        }

        map.extend(self.server_settings);

        map
    }
}

impl TryFrom<RawConnectionParameters<'_>> for ConnectionParameters {
    type Error = ParseError;

    fn try_from(raw_params: RawConnectionParameters<'_>) -> Result<Self, Self::Error> {
        fn merge_hosts_and_ports(
            host_types: &[Option<HostType>],
            mut specified_ports: &[Option<u16>],
        ) -> Result<Vec<Host>, ParseError> {
            let mut hosts = vec![];

            if host_types.is_empty() {
                return merge_hosts_and_ports(
                    &[
                        Some(HostType::Path("/var/run/postgresql".to_string())),
                        Some(HostType::Path("/run/postgresql".to_string())),
                        Some(HostType::Path("/tmp".to_string())),
                        Some(HostType::Path("/private/tmp".to_string())),
                        Some(HostType::Hostname("localhost".to_string())),
                    ],
                    specified_ports,
                );
            }

            if specified_ports.is_empty() {
                specified_ports = &[Some(5432)];
            } else if specified_ports.len() != host_types.len() && specified_ports.len() > 1 {
                return Err(ParseError::InvalidPortCount(format!("{specified_ports:?}")));
            }

            for (i, host_type) in host_types.iter().enumerate() {
                let host_type = host_type
                    .clone()
                    .unwrap_or_else(|| HostType::Path("/var/run/postgresql".to_string()));
                let port = specified_ports[i % specified_ports.len()].unwrap_or(5432);

                hosts.push(Host(host_type, port));
            }
            Ok(hosts)
        }

        let hosts = merge_hosts_and_ports(
            &raw_params.hosts.unwrap_or_default(),
            &raw_params.ports.unwrap_or_default(),
        )?;

        if hosts.is_empty() {
            return Err(ParseError::MissingRequiredParameter("host".to_string()));
        }

        let user = raw_params
            .user
            .ok_or_else(|| ParseError::MissingRequiredParameter("user".to_string()))?;
        let database = raw_params.database.unwrap_or_else(|| user.clone());

        let password = match raw_params.password {
            Some(p) => Password::Specified(p.into_owned()),
            None => match raw_params.passfile {
                Some(passfile) => Password::Passfile(passfile.into_owned().into()),
                None => Password::Unspecified,
            },
        };

        let connect_timeout = raw_params.connect_timeout.and_then(|seconds| {
            if seconds <= 0 {
                None
            } else {
                Some(Duration::from_secs(seconds.max(2) as u64))
            }
        });

        let any_tcp = hosts
            .iter()
            .any(|host| matches!(host.0, HostType::Hostname(..) | HostType::IP(..)));

        let ssl_mode = raw_params.sslmode.unwrap_or_else(|| {
            if any_tcp {
                SslMode::Prefer
            } else {
                SslMode::Disable
            }
        });

        let ssl = if ssl_mode == SslMode::Disable {
            Ssl::Disable
        } else {
            let mut ssl = SslParameters::default();
            if ssl_mode >= SslMode::Require {
                ssl.rootcert = raw_params
                    .sslrootcert
                    .map(|s| PathBuf::from(s.into_owned()));
                ssl.crl = raw_params.sslcrl.map(|s| PathBuf::from(s.into_owned()));
            }
            ssl.key = raw_params.sslkey.map(|s| PathBuf::from(s.into_owned()));
            ssl.cert = raw_params.sslcert.map(|s| PathBuf::from(s.into_owned()));
            ssl.min_protocol_version = raw_params.ssl_min_protocol_version;
            ssl.max_protocol_version = raw_params.ssl_max_protocol_version;
            ssl.password = raw_params.sslpassword.map(|s| s.into_owned());

            Ssl::Enable(ssl_mode, ssl)
        };

        Ok(ConnectionParameters {
            hosts,
            database: database.into_owned(),
            user: user.into_owned(),
            password,
            connect_timeout,
            server_settings: raw_params
                .server_settings
                .unwrap_or_default()
                .into_iter()
                .map(|(k, v)| (k.into_owned(), v.into_owned()))
                .collect(),
            ssl,
        })
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
#[allow(clippy::large_enum_variant)]
pub enum Ssl {
    #[default]
    Disable,
    Enable(SslMode, SslParameters),
}

/// SSL mode for PostgreSQL connections.
///
/// For more information, see the [PostgreSQL documentation](https://www.postgresql.org/docs/current/libpq-ssl.html).
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub enum SslMode {
    /// "I don't care about security, and I don't want to pay the overhead of encryption."
    #[serde(rename = "disable")]
    Disable,
    /// "I don't care about security, but I will pay the overhead of encryption if the server insists on it."
    #[serde(rename = "allow")]
    Allow,
    /// "I don't care about encryption, but I wish to pay the overhead of  encryption if the server supports it."
    #[serde(rename = "prefer")]
    Prefer,
    /// "I want my data to be encrypted, and I accept the overhead. I trust that the network will make sure I always connect to the server I want."
    #[serde(rename = "require")]
    Require,
    /// "I want my data encrypted, and I accept the overhead. I want to be sure that I connect to a server that I trust."
    #[serde(rename = "verify_ca")]
    VerifyCA,
    /// "I want my data encrypted, and I accept the overhead. I want to be sure that I connect to a server I trust, and that it's the one I specify."
    #[serde(rename = "verify_full")]
    VerifyFull,
}

impl TryFrom<&str> for SslMode {
    type Error = ParseError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        match s {
            "allow" => Ok(SslMode::Allow),
            "prefer" => Ok(SslMode::Prefer),
            "require" => Ok(SslMode::Require),
            "verify_ca" | "verify-ca" => Ok(SslMode::VerifyCA),
            "verify_full" | "verify-full" => Ok(SslMode::VerifyFull),
            "disable" => Ok(SslMode::Disable),
            _ => Err(ParseError::InvalidParameter(
                "sslmode".to_string(),
                s.to_string(),
            )),
        }
    }
}

impl ToString for SslMode {
    fn to_string(&self) -> String {
        match self {
            SslMode::Disable => "disable".to_string(),
            SslMode::Allow => "allow".to_string(),
            SslMode::Prefer => "prefer".to_string(),
            SslMode::Require => "require".to_string(),
            SslMode::VerifyCA => "verify-ca".to_string(),
            SslMode::VerifyFull => "verify-full".to_string(),
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SslVersion {
    Tls1,
    Tls1_1,
    Tls1_2,
    Tls1_3,
}

impl ToString for SslVersion {
    fn to_string(&self) -> String {
        match self {
            SslVersion::Tls1 => "TLSv1".to_string(),
            SslVersion::Tls1_1 => "TLSv1.1".to_string(),
            SslVersion::Tls1_2 => "TLSv1.2".to_string(),
            SslVersion::Tls1_3 => "TLSv1.3".to_string(),
        }
    }
}

impl serde::Serialize for SslVersion {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(match self {
            SslVersion::Tls1 => "TLSv1",
            SslVersion::Tls1_1 => "TLSv1.1",
            SslVersion::Tls1_2 => "TLSv1.2",
            SslVersion::Tls1_3 => "TLSv1.3",
        })
    }
}

impl<'a> TryFrom<Cow<'a, str>> for SslVersion {
    type Error = ParseError;
    fn try_from(value: Cow<str>) -> Result<SslVersion, Self::Error> {
        Ok(match value.to_lowercase().as_ref() {
            "tls_1" | "tlsv1" => SslVersion::Tls1,
            "tls_1.1" | "tlsv1.1" => SslVersion::Tls1_1,
            "tls_1.2" | "tlsv1.2" => SslVersion::Tls1_2,
            "tls_1.3" | "tlsv1.3" => SslVersion::Tls1_3,
            _ => return Err(ParseError::InvalidTLSVersion(value.to_string())),
        })
    }
}

impl Into<openssl::ssl::SslVersion> for SslVersion {
    fn into(self) -> openssl::ssl::SslVersion {
        match self {
            Self::Tls1 => openssl::ssl::SslVersion::TLS1,
            Self::Tls1_1 => openssl::ssl::SslVersion::TLS1_1,
            Self::Tls1_2 => openssl::ssl::SslVersion::TLS1_2,
            Self::Tls1_3 => openssl::ssl::SslVersion::TLS1_3,
        }
    }
}

#[derive(Default, Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SslParameters {
    pub cert: Option<PathBuf>,
    pub key: Option<PathBuf>,
    pub password: Option<String>,
    pub rootcert: Option<PathBuf>,
    pub crl: Option<PathBuf>,
    pub min_protocol_version: Option<SslVersion>,
    pub max_protocol_version: Option<SslVersion>,
    pub keylog_filename: Option<PathBuf>,
    pub verify_crl_check_chain: Option<bool>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct RawConnectionParameters<'a> {
    pub hosts: Option<Vec<Option<HostType>>>,
    pub ports: Option<Vec<Option<u16>>>,
    pub database: Option<Cow<'a, str>>,
    pub user: Option<Cow<'a, str>>,
    pub password: Option<Cow<'a, str>>,
    pub passfile: Option<Cow<'a, Path>>,
    pub connect_timeout: Option<isize>,
    pub sslmode: Option<SslMode>,
    pub sslcert: Option<Cow<'a, Path>>,
    pub sslkey: Option<Cow<'a, Path>>,
    pub sslpassword: Option<Cow<'a, str>>,
    pub sslrootcert: Option<Cow<'a, Path>>,
    pub sslcrl: Option<Cow<'a, Path>>,
    pub ssl_min_protocol_version: Option<SslVersion>,
    pub ssl_max_protocol_version: Option<SslVersion>,
    pub keylog_filename: Option<Cow<'a, Path>>,
    pub verify_crl_check_chain: Option<bool>,
    /// Any additional settings we don't recognize
    pub server_settings: Option<HashMap<Cow<'a, str>, Cow<'a, str>>>,
}

impl<'a> Into<HashMap<String, String>> for RawConnectionParameters<'a> {
    fn into(self) -> HashMap<String, String> {
        let mut map = HashMap::new();

        if let Some(hosts) = self.hosts {
            map.insert(
                "host".to_string(),
                hosts
                    .iter()
                    .map(|h| h.as_ref().map(|ht| ht.to_string()).unwrap_or_default())
                    .collect::<Vec<_>>()
                    .join(","),
            );
        }
        if let Some(ports) = self.ports {
            map.insert(
                "port".to_string(),
                ports
                    .iter()
                    .map(|p| p.map_or("".to_string(), |v| v.to_string()))
                    .collect::<Vec<_>>()
                    .join(","),
            );
        }
        if let Some(database) = self.database {
            map.insert("dbname".to_string(), database.into_owned());
        }
        if let Some(user) = self.user {
            map.insert("user".to_string(), user.into_owned());
        }
        if let Some(password) = self.password {
            map.insert("password".to_string(), password.into_owned());
        }
        if let Some(passfile) = self.passfile {
            map.insert(
                "passfile".to_string(),
                passfile.to_string_lossy().to_string(),
            );
        }
        if let Some(connect_timeout) = self.connect_timeout {
            map.insert("connect_timeout".to_string(), connect_timeout.to_string());
        }
        if let Some(sslmode) = self.sslmode {
            map.insert("sslmode".to_string(), sslmode.to_string());
        }
        if let Some(sslcert) = self.sslcert {
            map.insert("sslcert".to_string(), sslcert.to_string_lossy().to_string());
        }
        if let Some(sslkey) = self.sslkey {
            map.insert("sslkey".to_string(), sslkey.to_string_lossy().to_string());
        }
        if let Some(sslpassword) = self.sslpassword {
            map.insert("sslpassword".to_string(), sslpassword.into_owned());
        }
        if let Some(sslrootcert) = self.sslrootcert {
            map.insert(
                "sslrootcert".to_string(),
                sslrootcert.to_string_lossy().to_string(),
            );
        }
        if let Some(sslcrl) = self.sslcrl {
            map.insert("sslcrl".to_string(), sslcrl.to_string_lossy().to_string());
        }
        if let Some(ssl_min_protocol_version) = self.ssl_min_protocol_version {
            map.insert(
                "ssl_min_protocol_version".to_string(),
                ssl_min_protocol_version.to_string(),
            );
        }
        if let Some(ssl_max_protocol_version) = self.ssl_max_protocol_version {
            map.insert(
                "ssl_max_protocol_version".to_string(),
                ssl_max_protocol_version.to_string(),
            );
        }
        if let Some(keylog_filename) = self.keylog_filename {
            map.insert(
                "keylog_filename".to_string(),
                keylog_filename.to_string_lossy().to_string(),
            );
        }
        if let Some(verify_crl_check_chain) = self.verify_crl_check_chain {
            map.insert(
                "verify_crl_check_chain".to_string(),
                verify_crl_check_chain.to_string(),
            );
        }
        if let Some(server_settings) = self.server_settings {
            map.extend(
                server_settings
                    .into_iter()
                    .map(|(k, v)| (k.into_owned(), v.into_owned())),
            );
        }

        map
    }
}

impl Ssl {
    /// Resolve the SSL paths relative to the home directory.
    pub fn resolve(&mut self, home_dir: &Path) -> Result<(), std::io::Error> {
        let postgres_dir = home_dir;
        let Ssl::Enable(mode, params) = self else {
            return Ok(());
        };
        if *mode >= SslMode::Require {
            let root_cert = params
                .rootcert
                .clone()
                .unwrap_or_else(|| postgres_dir.join("root.crt"));
            if root_cert.exists() {
                params.rootcert = Some(root_cert);
            } else if *mode > SslMode::Require {
                return Err(std::io::Error::new(ErrorKind::NotFound,
                    format!("Root certificate not found: {root_cert:?}. Either provide the file or change sslmode to disable SSL certificate verification.")));
            }

            let crl = params
                .crl
                .clone()
                .unwrap_or_else(|| postgres_dir.join("root.crl"));
            if crl.exists() {
                params.crl = Some(crl);
            }
        }
        let key = params
            .key
            .clone()
            .unwrap_or_else(|| postgres_dir.join("postgresql.key"));
        if key.exists() {
            params.key = Some(key);
        }
        let cert = params
            .cert
            .clone()
            .unwrap_or_else(|| postgres_dir.join("postgresql.crt"));
        if cert.exists() {
            params.cert = Some(cert);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{HostType, ParseError};
    use rstest::rstest;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    #[rstest]
    #[case("example.com", HostType::Hostname("example.com".to_string()))]
    // This should probably parse as IPv4
    #[case("0", HostType::Hostname("0".to_string()))]
    #[case(
        "192.168.1.1",
        HostType::IP(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), None)
    )]
    #[case(
        "2001:db8::1",
        HostType::IP(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)), None)
    )]
    #[case("2001:db8::1%eth0", HostType::IP(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)), Some("eth0".to_string())))]
    #[case("/var/run/postgresql", HostType::Path("/var/run/postgresql".to_string()))]
    #[case("@abstract", HostType::Abstract("abstract".to_string()))]
    fn test_host_type_roundtrip(#[case] input: &str, #[case] expected: HostType) {
        let parsed = HostType::try_from_str(input).unwrap();
        assert_eq!(parsed, expected, "{input} should have succeeded");
        assert_eq!(parsed.to_string(), input, "{input} should have succeeded");
    }

    #[rstest]
    #[case("", ParseError::InvalidHostname("".to_string()))]
    #[case("example.com:80", ParseError::InvalidHostname("example.com:80".to_string()))]
    #[case("[::1]", ParseError::InvalidHostname("[::1]".to_string()))]
    #[case("2001:db8::1%", ParseError::InvalidHostname("2001:db8::1%".to_string()))]
    #[case("not:valid:ipv6", ParseError::InvalidHostname("not:valid:ipv6".to_string()))]
    fn test_host_type_failures(#[case] input: &str, #[case] expected_error: ParseError) {
        let result = HostType::try_from_str(input);
        assert!(result.is_err(), "{input} should have failed");
        assert_eq!(
            result.unwrap_err(),
            expected_error,
            "{input} should have failed"
        );
    }

    #[test]
    fn resolve() {
        eprintln!(
            "{:?}",
            HostType::Hostname("fe80::127c:61ff:fe3d:16d5%lo".to_owned()).resolve()
        );
    }
}
