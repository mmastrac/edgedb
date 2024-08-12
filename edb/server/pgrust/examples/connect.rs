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
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

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
                    let q1 = conn.query("select 1; select 1;");
                    let q2 = conn.query("select 1;");
                    tokio::task::spawn_local(q1);
                    tokio::task::spawn_local(q2);
                }
                _ => return Err("Must specify either a TCP address or a Unix socket path".into()),
            }
            Result::<(), Box<dyn std::error::Error>>::Ok(())
        })
        .await?;
    local.await;

    Ok(())
}
