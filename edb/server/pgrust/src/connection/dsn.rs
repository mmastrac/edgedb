//! Parses DSNs for database connections. There are some small differences with
//! how `libpq` works:
//!
//!  - Unrecognized options are supported and collected in a map.
//!  - `database` is recognized as an alias for `dbname`
//!  - [host1,host2] is considered valid for psql
use super::params::*;
use percent_encoding::percent_decode_str;
use std::borrow::Cow;
use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use url::Url;

#[cfg(windows)]
const PGPASSFILE: &str = "pgpass.conf";
#[cfg(not(windows))]
const PGPASSFILE: &str = ".pgpass";

impl Password {
    /// Attempt to resolve a password against the given homedir.
    pub fn resolve(
        &mut self,
        home: &Path,
        hosts: &[Host],
        database: &str,
        user: &str,
    ) -> Result<Option<PasswordWarning>, std::io::Error> {
        let passfile = match self {
            Password::Unspecified => {
                let passfile = home.join(PGPASSFILE);
                // Don't warn about implicit missing or inaccessible files
                if !matches!(passfile.try_exists(), Ok(true)) {
                    *self = Password::Unspecified;
                    return Ok(None);
                }
                if !passfile.is_file() {
                    *self = Password::Unspecified;
                    return Ok(None);
                }
                passfile
            }
            Password::Specified(_) => return Ok(None),
            Password::Passfile(passfile) => {
                let passfile = passfile.clone();
                if matches!(passfile.try_exists(), Ok(false)) {
                    *self = Password::Unspecified;
                    return Ok(Some(PasswordWarning::NotExists(passfile)));
                }
                if passfile.exists() && !passfile.is_file() {
                    *self = Password::Unspecified;
                    return Ok(Some(PasswordWarning::NotFile(passfile)));
                }
                passfile
            }
        };

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            let metadata = match passfile.metadata() {
                Err(err) if err.kind() == ErrorKind::PermissionDenied => {
                    *self = Password::Unspecified;
                    return Ok(Some(PasswordWarning::NotAccessible(passfile)));
                }
                res => res?,
            };
            let permissions = metadata.permissions();
            let mode = permissions.mode();

            if mode & (0o070) != 0 {
                *self = Password::Unspecified;
                return Ok(Some(PasswordWarning::Permissions(passfile, mode)));
            }
        }

        let file = match OpenOptions::new().read(true).open(&passfile) {
            Err(err) if err.kind() == ErrorKind::PermissionDenied => {
                *self = Password::Unspecified;
                return Ok(Some(PasswordWarning::NotAccessible(passfile)));
            }
            res => res?,
        };
        if let Some(password) = read_password_file(
            hosts,
            database,
            user,
            std::io::read_to_string(file)?.split('\n'),
        ) {
            *self = Password::Specified(password);
        } else {
            *self = Password::Unspecified;
        }
        Ok(None)
    }
}

pub trait UserProfile {
    fn username(&self) -> Option<Cow<str>>;
    fn homedir(&self) -> Option<Cow<str>>;
}

pub trait EnvVar {
    fn read(&self, name: &'static str) -> Option<Cow<str>>;
}

impl<K, V> EnvVar for HashMap<K, V>
where
    K: std::hash::Hash + Eq + std::borrow::Borrow<str>,
    V: std::borrow::Borrow<str>,
{
    fn read(&self, name: &'static str) -> Option<Cow<str>> {
        self.get(name).map(|value| value.borrow().into())
    }
}

impl EnvVar for std::env::Vars {
    fn read(&self, name: &'static str) -> Option<Cow<str>> {
        if let Ok(value) = std::env::var(name) {
            Some(value.into())
        } else {
            None
        }
    }
}

impl EnvVar for &[(&str, &str)] {
    fn read(&self, name: &'static str) -> Option<Cow<str>> {
        for (key, value) in self.iter() {
            if *key == name {
                return Some((*value).into());
            }
        }
        None
    }
}

impl EnvVar for () {
    fn read(&self, _: &'static str) -> Option<Cow<str>> {
        None
    }
}

fn maybe_decode(str: Cow<str>) -> Cow<str> {
    if str.contains('%') {
        if let Ok(str) = percent_decode_str(&str).decode_utf8() {
            str.into_owned().into()
        } else {
            str.into_owned().into()
        }
    } else {
        str
    }
}

fn parse_port(port: &str) -> Result<Option<u16>, ParseError> {
    if port.is_empty() {
        Ok(None)
    } else if port.contains('%') {
        let decoded = percent_decode_str(port)
            .decode_utf8()
            .map_err(|_| ParseError::InvalidPort(port.to_string()))?;
        Ok(Some(
            decoded
                .parse::<u16>()
                .map_err(|_| ParseError::InvalidPort(port.to_string()))?,
        ))
    } else {
        Ok(Some(
            port.parse::<u16>()
                .map_err(|_| ParseError::InvalidPort(port.to_string()))?,
        ))
    }
}

fn parse_hostlist<I, S>(
    hostspecs: I,
) -> Result<(Vec<Option<HostType>>, Vec<Option<u16>>), ParseError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut hosts = vec![];
    let mut ports = vec![];
    let mut non_empty_host = false;
    let mut non_empty_port = false;

    for hostspec in hostspecs {
        let hostspec = hostspec.as_ref();
        let (host, port) = if hostspec.starts_with(':') {
            (None, parse_port(&hostspec[1..])?)
        } else if hostspec.starts_with('/') {
            (Some(HostType::Path(hostspec.to_string())), None)
        } else if hostspec.starts_with('[') {
            let end_bracket = hostspec
                .find(']')
                .ok_or_else(|| ParseError::InvalidHostname(hostspec.to_string()))?;

            let (host_part, port_part) = hostspec.split_at(end_bracket + 1);
            let host = HostType::try_from_str(&host_part[1..end_bracket])?;

            let port = if let Some(stripped) = port_part.strip_prefix(':') {
                parse_port(stripped)?
            } else if !port_part.is_empty() {
                return Err(ParseError::InvalidHostname(hostspec.to_string()));
            } else {
                None
            };
            (Some(host), port)
        } else {
            let parts: Vec<&str> = hostspec.split(':').collect();
            let addr = parts[0].to_string();
            let port = if parts.len() > 1 && !parts[1].is_empty() {
                parse_port(parts[1])?
            } else {
                None
            };

            if let Ok(ip) = Ipv4Addr::from_str(&addr) {
                (Some(HostType::IP(IpAddr::V4(ip), None)), port)
            } else {
                (Some(HostType::Hostname(addr)), port)
            }
        };

        non_empty_host |= host.is_some();
        hosts.push(host);
        non_empty_port |= port.is_some();
        ports.push(port);
    }
    if !non_empty_host && hosts.len() == 1 {
        hosts.clear();
    }
    if !non_empty_port && ports.len() == 1 {
        ports.clear();
    }
    Ok((hosts, ports))
}

fn parse_host_param(value: &str) -> Result<Vec<Option<HostType>>, ParseError> {
    value
        .split(',')
        .map(|host| {
            if host.is_empty() {
                Ok(None)
            } else {
                HostType::try_from_str(host).map(Some)
            }
        })
        .collect()
}

fn parse_port_param(value: &str) -> Result<Vec<Option<u16>>, ParseError> {
    value
        .split(',')
        .map(parse_port)
        .collect::<Result<Vec<Option<u16>>, _>>()
}

fn parse_connect_timeout(timeout: Cow<str>) -> Result<isize, ParseError> {
    let seconds = timeout.parse::<isize>().map_err(|_| {
        ParseError::InvalidParameter("connect_timeout".to_string(), timeout.to_string())
    })?;
    Ok(seconds)
}

pub fn parse_postgres_dsn(url_str: &str) -> Result<RawConnectionParameters, ParseError> {
    let url_str = if let Some(url) = url_str.strip_prefix("postgres://") {
        url
    } else if let Some(url) = url_str.strip_prefix("postgresql://") {
        url
    } else {
        return Err(ParseError::InvalidScheme(
            url_str.split(':').next().unwrap_or_default().to_owned(),
        ));
    };

    // Validate percent encoding
    let mut chars = url_str.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '%' {
            let hex1 = chars.next().ok_or(ParseError::InvalidPercentEncoding)?;
            let hex2 = chars.next().ok_or(ParseError::InvalidPercentEncoding)?;

            if !hex1.is_ascii_hexdigit() || !hex2.is_ascii_hexdigit() {
                return Err(ParseError::InvalidPercentEncoding);
            }

            // Check for %00
            if hex1 == '0' && hex2 == '0' {
                return Err(ParseError::InvalidPercentEncoding);
            }
        }
    }

    // Postgres allows for hostnames surrounded by [] to contain pathnames
    let (authority, path_and_query) = {
        let mut in_brackets = false;
        let mut chars = url_str.char_indices();

        loop {
            if let Some((i, c)) = chars.next() {
                match c {
                    '[' => in_brackets = true,
                    ']' => in_brackets = false,
                    '?' | '/' if !in_brackets => {
                        break url_str.split_at(i);
                    }
                    _ => {}
                }
            } else {
                if in_brackets {
                    return Err(ParseError::InvalidHostname(url_str.to_string()));
                }
                break (url_str, "");
            }
        }
    };

    let (auth, host) = match authority.split_once('@') {
        Some((auth, host)) => (auth, host),
        None => ("", authority),
    };

    let url = Url::parse(&format!("unused://{auth}@host{path_and_query}"))?;

    let mut raw_params = RawConnectionParameters::<'static>::default();
    let mut server_settings = HashMap::new();

    if host.is_empty() {
        raw_params.hosts = None;
        raw_params.ports = None;
    } else {
        let (hosts, ports) = parse_hostlist(maybe_decode(host.into()).split(','))?;
        if !hosts.is_empty() {
            raw_params.hosts = Some(hosts);
        }
        if !ports.is_empty() {
            raw_params.ports = Some(ports);
        }
    };

    raw_params.user = match url.username() {
        "" => None,
        user => {
            let decoded = percent_decode_str(user);
            if let Ok(user) = decoded.decode_utf8() {
                Some(Cow::Owned(user.to_string()))
            } else {
                Some(Cow::Owned(user.to_string()))
            }
        }
    };
    raw_params.password = url
        .password()
        .map(|p| p.into())
        .map(maybe_decode)
        .map(|s| s.into_owned())
        .map(Cow::Owned);
    raw_params.database = match url.path() {
        "" | "/" => None,
        path => Some(Cow::Owned(path.trim_start_matches('/').to_string())),
    }
    .map(maybe_decode)
    .map(|s| s.into_owned())
    .map(Cow::Owned);

    // Validate URL query parameters
    let query_str = url.query().unwrap_or("");
    let mut key_value_pairs = query_str.split('&');

    while let Some(pair) = key_value_pairs.next() {
        if pair.is_empty() {
            continue;
        }

        if !pair.contains('=') {
            return Err(ParseError::InvalidQueryParameter(pair.to_string()));
        }

        let parts: Vec<&str> = pair.split('=').collect();
        if parts.len() > 2 {
            return Err(ParseError::InvalidQueryParameter(pair.to_string()));
        }

        if parts[0].is_empty() {
            return Err(ParseError::InvalidQueryParameter(pair.to_string()));
        }
    }

    for (name, value) in url.query_pairs() {
        match name.as_ref() {
            "host" => {
                let hosts = parse_host_param(&value)?;
                if !hosts.is_empty() {
                    raw_params.hosts = Some(hosts);
                }
            }
            "port" => {
                raw_params.ports = Some(parse_port_param(&value)?);
            }
            // Intentional difference with libpq: database is not a valid param
            "dbname" | "database" => {
                raw_params.database = Some(value.to_string().into());
            }
            "user" => {
                raw_params.user = Some(value.to_string().into());
            }
            "password" => {
                raw_params.password = Some(value.to_string().into());
            }
            "passfile" => raw_params.passfile = Some(PathBuf::from(value.to_string()).into()),
            "connect_timeout" => raw_params.connect_timeout = Some(parse_connect_timeout(value)?),
            "sslmode" => raw_params.sslmode = Some(SslMode::try_from(value.as_ref())?),
            "sslcert" => raw_params.sslcert = Some(PathBuf::from(value.to_string()).into()),
            "sslkey" => raw_params.sslkey = Some(PathBuf::from(value.to_string()).into()),
            "sslpassword" => raw_params.sslpassword = Some(value.to_string().into()),
            "sslrootcert" => raw_params.sslrootcert = Some(PathBuf::from(value.to_string()).into()),
            "sslcrl" => raw_params.sslcrl = Some(PathBuf::from(value.to_string()).into()),
            "ssl_min_protocol_version" => {
                raw_params.ssl_min_protocol_version = Some(value.try_into()?)
            }
            "ssl_max_protocol_version" => {
                raw_params.ssl_max_protocol_version = Some(value.try_into()?)
            }
            name => {
                let name = Cow::<str>::Owned(name.to_string());
                server_settings.insert(name.into(), value.to_string().into());
            }
        };
    }

    if !server_settings.is_empty() {
        raw_params.server_settings = Some(server_settings);
    }

    Ok(raw_params)
}

fn apply_env_to_raw_params(
    mut raw_params: RawConnectionParameters,
    env: impl EnvVar,
) -> Result<RawConnectionParameters, ParseError> {
    if raw_params.hosts.is_none() {
        raw_params.hosts = env
            .read("PGHOST")
            .map(|pghost| parse_host_param(&pghost))
            .transpose()?;
    }

    if raw_params.ports.is_none() {
        raw_params.ports = env
            .read("PGPORT")
            .map(|value| {
                value
                    .split(',')
                    .map(parse_port)
                    .collect::<Result<Vec<Option<u16>>, _>>()
            })
            .transpose()?;
    }

    if raw_params.user.is_none() {
        raw_params.user = env.read("PGUSER").map(|s| Cow::Owned(s.to_string()));
    }

    if raw_params.password.is_none() {
        raw_params.password = env.read("PGPASSWORD").map(|s| Cow::Owned(s.to_string()));
    }

    if raw_params.database.is_none() {
        raw_params.database = env.read("PGDATABASE").map(|s| Cow::Owned(s.to_string()));
    }

    if raw_params.passfile.is_none() {
        raw_params.passfile = env
            .read("PGPASSFILE")
            .map(|s| Cow::Owned(PathBuf::from(s.to_string())));
    }

    if raw_params.connect_timeout.is_none() {
        raw_params.connect_timeout = env
            .read("PGCONNECT_TIMEOUT")
            .map(|v| parse_connect_timeout(v))
            .transpose()?;
    }

    if raw_params.sslmode.is_none() {
        raw_params.sslmode = env
            .read("PGSSLMODE")
            .map(|s| SslMode::try_from(s.as_ref()))
            .transpose()?;
    }

    if raw_params.sslrootcert.is_none() {
        raw_params.sslrootcert = env
            .read("PGSSLROOTCERT")
            .map(|s| Cow::Owned(PathBuf::from(s.to_string())));
    }

    if raw_params.sslcrl.is_none() {
        raw_params.sslcrl = env
            .read("PGSSLCRL")
            .map(|s| Cow::Owned(PathBuf::from(s.to_string())));
    }

    if raw_params.sslkey.is_none() {
        raw_params.sslkey = env
            .read("PGSSLKEY")
            .map(|s| Cow::Owned(PathBuf::from(s.to_string())));
    }

    if raw_params.sslcert.is_none() {
        raw_params.sslcert = env
            .read("PGSSLCERT")
            .map(|s| Cow::Owned(PathBuf::from(s.to_string())));
    }

    if raw_params.ssl_min_protocol_version.is_none() {
        raw_params.ssl_min_protocol_version = env
            .read("PGSSLMINPROTOCOLVERSION")
            .and_then(|s| s.try_into().ok());
    }

    if raw_params.ssl_max_protocol_version.is_none() {
        raw_params.ssl_max_protocol_version = env
            .read("PGSSLMAXPROTOCOLVERSION")
            .and_then(|s| s.try_into().ok());
    }

    Ok(raw_params)
}

pub fn parse_postgres_dsn_env(
    url_str: &str,
    env: impl EnvVar,
) -> Result<ConnectionParameters, ParseError> {
    let raw_params = parse_postgres_dsn(url_str)?;
    let raw_params = apply_env_to_raw_params(raw_params, env)?;
    raw_params.try_into()
}

fn read_password_file(
    hosts: &[Host],
    database: &str,
    user: &str,
    reader: impl Iterator<Item = impl AsRef<str>>,
) -> Option<String> {
    for line in reader {
        let line = line.as_ref().trim();

        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let mut parts = vec![String::new()];
        let mut backslash = false;
        for c in line.chars() {
            if backslash {
                parts.last_mut().unwrap().push(c);
                backslash = false;
                continue;
            }
            if c == '\\' {
                backslash = true;
                continue;
            }
            if c == ':' && parts.len() <= 4 {
                parts.push(String::new());
                continue;
            }
            parts.last_mut().unwrap().push(c);
        }

        if parts.len() == 5 {
            for host in hosts {
                match &host.0 {
                    HostType::Hostname(hostname) => {
                        if parts[0] != "*" && parts[0] != hostname.as_str() {
                            continue;
                        }
                    }
                    HostType::IP(hostname, _) => {
                        if parts[0] != "*" && str::parse(&parts[0]) != Ok(*hostname) {
                            continue;
                        }
                    }
                    HostType::Path(_) | HostType::Abstract(_) => {
                        if parts[0] != "*" && parts[0] != "localhost" {
                            continue;
                        }
                    }
                };
                if parts[1] != "*" && str::parse(&parts[1]) != Ok(host.1) {
                    continue;
                }
                if parts[2] != "*" && parts[2] != database {
                    continue;
                }
                if parts[3] != "*" && parts[3] != user {
                    continue;
                }
                return Some(parts.pop().unwrap());
            }
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use pretty_assertions::assert_eq;
    use rstest::rstest;

    #[rstest]
    #[case(
        &[":1"],
        Ok((vec![], vec![Some(1)]))
    )]
    #[case(
        &[":1", ":2"],
        Ok((vec!["", ""], vec![Some(1), Some(2)]))
    )]
    #[case(
        &["hostname"],
        Ok((vec!["hostname"], vec![]))
    )]
    #[case(
        &["hostname:4321"],
        Ok((vec!["hostname"], vec![Some(4321)]))
    )]
    #[case(
        &["/path"],
        Ok((vec!["/path"], vec![]))
    )]
    #[case(
        &["[2001:db8::1234]", "[::1]"],
        Ok((vec!["2001:db8::1234", "::1"], vec![None, None]))
    )]
    #[case(
        &["[2001:db8::1234%eth0]"],
        Ok((vec!["2001:db8::1234%eth0"], vec![]))
    )]
    #[case(
        &["[::1]z"],
        Err(ParseError::InvalidHostname("[::1]z".to_owned()))
    )]
    fn test_parse_hostlist(
        #[case] input: &[&str],
        #[case] expected: Result<(Vec<&'static str>, Vec<Option<u16>>), ParseError>,
    ) {
        let result = parse_hostlist(input);
        let expected_host_types = expected.map(|(hosts, ports)| {
            (
                hosts
                    .into_iter()
                    .map(|h| HostType::try_from_str(h).ok())
                    .collect(),
                ports,
            )
        });
        assert_eq!(expected_host_types, result);
    }

    #[test]
    fn test_parse_password_file() {
        let input = r#"
abc:*:*:user:password from pgpass for user@abc
localhost:*:*:*:password from pgpass for localhost
cde:5433:*:*:password from pgpass for cde:5433

*:*:*:testuser:password from pgpass for testuser
*:*:testdb:*:password from pgpass for testdb
# comment
*:*:test\:db:test\\:password from pgpass with escapes
        "#
        .trim();

        for (host, database, user, output) in [
            (
                Host(HostType::Hostname("abc".to_owned()), 1234),
                "database",
                "user",
                Some("password from pgpass for user@abc"),
            ),
            (
                Host(HostType::Hostname("localhost".to_owned()), 1234),
                "database",
                "user",
                Some("password from pgpass for localhost"),
            ),
            (
                Host(HostType::Path("/tmp".into()), 1234),
                "database",
                "user",
                Some("password from pgpass for localhost"),
            ),
            (
                Host(HostType::Hostname("hmm".to_owned()), 1234),
                "database",
                "testuser",
                Some("password from pgpass for testuser"),
            ),
            (
                Host(HostType::Hostname("hostname".to_owned()), 1234),
                "test:db",
                r#"test\"#,
                Some("password from pgpass with escapes"),
            ),
            (
                Host(HostType::Hostname("doesntexist".to_owned()), 1234),
                "db",
                "user",
                None,
            ),
        ] {
            assert_eq!(
                read_password_file(&[host], database, user, input.split('\n')),
                output.map(|s| s.to_owned())
            );
        }
    }

    #[test]
    fn test_parse_dsn() {
        assert_eq!(
            parse_postgres_dsn_env(
                "postgres://",
                [
                    ("PGUSER", "user"),
                    ("PGDATABASE", "testdb"),
                    ("PGPASSWORD", "passw"),
                    ("PGHOST", "host"),
                    ("PGPORT", "123"),
                    ("PGCONNECT_TIMEOUT", "8"),
                ]
                .as_slice()
            )
            .unwrap(),
            ConnectionParameters {
                hosts: vec![Host(HostType::Hostname("host".to_string()), 123)],
                database: "testdb".to_string(),
                user: "user".to_string(),
                password: Password::Specified("passw".to_string()),
                connect_timeout: Some(Duration::from_secs(8)),
                ssl: Ssl::Enable(SslMode::Prefer, Default::default()),
                ..Default::default()
            }
        );

        assert_eq!(
            parse_postgres_dsn_env("postgres://user:pass@host:1234/database", ()).unwrap(),
            ConnectionParameters {
                hosts: vec![Host(HostType::Hostname("host".to_string()), 1234)],
                database: "database".to_string(),
                user: "user".to_string(),
                password: Password::Specified("pass".to_string()),
                ssl: Ssl::Enable(SslMode::Prefer, Default::default()),
                ..Default::default()
            }
        );

        assert_eq!(
            parse_postgres_dsn_env("postgresql://user@host1:1111,host2:2222/db", ()).unwrap(),
            ConnectionParameters {
                hosts: vec![
                    Host(HostType::Hostname("host1".to_string()), 1111),
                    Host(HostType::Hostname("host2".to_string()), 2222),
                ],
                database: "db".to_string(),
                user: "user".to_string(),
                password: Password::Unspecified,
                ssl: Ssl::Enable(SslMode::Prefer, Default::default()),
                ..Default::default()
            }
        );
    }

    #[test]
    fn test_dsn_with_slashes() {
        assert_eq!(
            parse_postgres_dsn_env(
                r#"postgres://test\\@fgh/test\:db?passfile=/tmp/tmpkrjuaje4"#,
                ()
            )
            .unwrap(),
            ConnectionParameters {
                hosts: vec![Host(HostType::Hostname("fgh".to_string()), 5432)],
                database: r#"test\:db"#.to_string(),
                user: r#"test\\"#.to_string(),
                password: Password::Passfile("/tmp/tmpkrjuaje4".to_string().into()),
                ssl: Ssl::Enable(SslMode::Prefer, Default::default()),
                ..Default::default()
            }
        );
    }

    #[test]
    fn test_dsn_with_escapes() {
        assert_eq!(
            parse_postgres_dsn_env("postgresql://us%40r:p%40ss@h%40st1,h%40st2:543%33/d%62", ())
                .unwrap(),
            ConnectionParameters {
                hosts: vec![
                    Host(HostType::Hostname("h@st1".to_string()), 5432),
                    Host(HostType::Hostname("h@st2".to_string()), 5433),
                ],
                database: "db".to_string(),
                user: "us@r".to_string(),
                password: Password::Specified("p@ss".to_string()),
                ssl: Ssl::Enable(SslMode::Prefer, Default::default()),
                ..Default::default()
            }
        );
    }

    #[test]
    fn test_dsn_no_slash() {
        assert_eq!(
            parse_postgres_dsn_env("postgres://user@?port=56226&host=%2Ftmp", ()).unwrap(),
            ConnectionParameters {
                hosts: vec![Host(HostType::Path("/tmp".to_string()), 56226)],
                database: "user".to_string(),
                user: "user".to_string(),
                password: Password::Unspecified,
                ssl: Ssl::Disable,
                ..Default::default()
            }
        );
    }
}
