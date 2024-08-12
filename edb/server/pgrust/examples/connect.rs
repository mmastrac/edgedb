use clap::Parser;
use clap_derive::Parser;
use pgrust::{Client, ConnectionParameters};
use std::net::SocketAddr;
use tokio::{
    net::{TcpStream, UnixSocket},
    task::LocalSet,
};

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Network socket address and port
    #[clap(short = 't', long = "tcp", value_parser, conflicts_with = "unix")]
    tcp: Option<SocketAddr>,

    /// Unix socket path
    #[clap(short = 'u', long = "unix", value_parser, conflicts_with = "tcp")]
    unix: Option<String>,

    /// Username to use for the connection
    #[clap(
        short = 'U',
        long = "username",
        value_parser,
        default_value = "postgres"
    )]
    username: String,

    /// Username to use for the connection
    #[clap(short = 'P', long = "password", value_parser, default_value = "")]
    password: String,

    /// Database to use for the connection
    #[clap(
        short = 'd',
        long = "database",
        value_parser,
        default_value = "postgres"
    )]
    database: String,

    /// SQL statements to run
    #[clap(
        name = "statements",
        trailing_var_arg = true,
        allow_hyphen_values = true,
        help = "Zero or more SQL statements to run (defaults to 'select 1')"
    )]
    statements: Option<Vec<String>>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    eprintln!("{args:?}");

    let local = LocalSet::new();
    local
        .run_until(async {
            match (args.tcp, args.unix) {
                (Some(addr), None) => {
                    // Connect to the port with tokio
                    let _client = TcpStream::connect(addr).await?;
                    unimplemented!()
                }
                (None, Some(path)) => {
                    // Connect to the unix stream socket
                    let socket = UnixSocket::new_stream()?;
                    let client = socket.connect(path).await?;
                    let (conn, task) = Client::new(
                        ConnectionParameters {
                            username: args.username,
                            password: args.password,
                            database: args.database,
                        },
                        client,
                    );
                    tokio::task::spawn_local(task);
                    conn.ready().await?;

                    let local = LocalSet::new();
                    let statements = args
                        .statements
                        .unwrap_or_else(|| vec!["select 1;".to_string()]);
                    eprintln!("{statements:?}");
                    for statement in statements {
                        local.spawn_local(conn.query(&statement));
                    }
                    local.await;
                }
                _ => return Err("Must specify either a TCP address or a Unix socket path".into()),
            }
            Result::<(), Box<dyn std::error::Error>>::Ok(())
        })
        .await?;

    Ok(())
}
