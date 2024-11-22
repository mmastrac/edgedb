"""
This module implements a Rust-based transport for PostgreSQL connections.

The PGRawConn class provides a high-level interface for establishing and
managing PostgreSQL connections using a Rust-implemented state machine. It
handles the complexities of connection establishment, including SSL negotiation
and authentication, while presenting a simple asyncio-like transport interface
to the caller.
"""

import asyncio
import ssl as ssl_module
from typing import Optional, List, Tuple, Protocol, Callable, Dict, Self, Any
from enum import Enum, auto, IntEnum
from edb.server._rust_native.module._pg_rust import PyConnectionState
from dataclasses import dataclass

class ConnectionStateType(Enum):
    CONNECTING = 0
    SSL_CONNECTING = auto()
    AUTHENTICATING = auto()
    SYNCHRONIZING = auto()
    READY = auto()

class Authentication(Enum):
    NONE = 0
    PASSWORD = auto()
    MD5 = auto()
    SCRAM_SHA256 = auto()

@dataclass
class PGState:
    parameters: Dict[str, str]
    cancellation_key: Optional[Tuple[int, int]]
    auth: Optional[Authentication]

# class PyConnectionState:
#     def is_ready(self) -> bool: ...
#     def read_ssl_response(self) -> bool: ...
#     def drive_initial(self) -> None: ...
#     def drive_message(self, data: memoryview) -> None: ...
#     def drive_ssl_ready(self) -> None: ...
#     def get_ssl_context(self) -> ssl.SSLContext: ...
#     @property
#     def host_candidates(self) -> List[Tuple[str, str, int]]: ...

class ConnectionStateUpdate(Protocol):
    def send(self, message: memoryview) -> None: ...
    def upgrade(self) -> None: ...
    def parameter(self, name: str, value: str) -> None: ...
    def cancellation_key(self, pid: int, key: int) -> None: ...
    def state_changed(self, state: int) -> None: ...
    def auth(self, auth: int) -> None: ...

StateChangeCallback = Callable[[ConnectionStateType], None]

class SSLMode(IntEnum):
    disable = 0
    allow = 1
    prefer = 2
    require = 3
    verify_ca = 4
    verify_full = 5

    @classmethod
    def parse(cls, sslmode: str) -> Self:
        return getattr(cls, sslmode.replace('-', '_'))

def _parse_tls_version(tls_version: str) -> ssl_module.TLSVersion:
    if tls_version.startswith('SSL'):
        raise ValueError(
            f"Unsupported TLS version: {tls_version}"
        )
    try:
        return ssl_module.TLSVersion[tls_version.replace('.', '_')]
    except KeyError:
        raise ValueError(
            f"No such TLS version: {tls_version}"
        )

def _create_ssl(sslmode: SSLMode, ssl_config: Dict[str, Any]):
    ssl = ssl_module.SSLContext(ssl_module.PROTOCOL_TLS_CLIENT)
    ssl.check_hostname = sslmode >= SSLMode.verify_full
    if sslmode < SSLMode.require:
        ssl.verify_mode = ssl_module.CERT_NONE
    else:
        if ssl_config['rootcert']:
            ssl.load_verify_locations(ssl_config['rootcert'])
            ssl.verify_mode = ssl_module.CERT_REQUIRED
        else:
            if sslmode == SSLMode.require:
                ssl.verify_mode = ssl_module.CERT_NONE
        if ssl_config['crl']:
            ssl.load_verify_locations(ssl_config['crl'])
            ssl.verify_flags |= ssl_module.VERIFY_CRL_CHECK_CHAIN
    if ssl_config['key'] and ssl_config['cert']:
        ssl.load_cert_chain(ssl_config['cert'],
                            ssl_config['key'],
                            ssl_config['password'] or '')
    if ssl_config['max_protocol_version']:
        ssl.maximum_version = _parse_tls_version(
            ssl_config['max_protocol_version'])
    if ssl_config['min_protocol_version']:
        ssl.minimum_version = _parse_tls_version(
            ssl_config['min_protocol_version'])
    # OpenSSL 1.1.1 keylog file
    if hasattr(ssl, 'keylog_filename'):
        if ssl_config['keylog_filename']:
            ssl.keylog_filename = ssl_config['keylog_filename']
    return ssl

class PGConnectionProtocol(asyncio.Protocol):
    """A protocol that manages the initial connection and authentication process
    for PostgreSQL.

    This protocol acts as an intermediary between the raw socket connection and
    the user's protocol.
    """
    def __init__(self, state: PyConnectionState,
                 protocol: asyncio.Protocol,
                 ready_future: asyncio.Future):
        self.state = state
        self.protocol = protocol
        self.ready_future = ready_future
        self._writing_paused = False
        self._ready = False

    def data_received(self, data: bytes):
        if self._ready:
            self.protocol.data_received(data)
        else:
            self.state.drive_message(memoryview(data))
            if self.state.is_ready():
                self._ready = True
                self.ready_future.set_result(True)

    def connection_lost(self, exc):
        if self._ready:
            self.protocol.connection_lost(exc)
        else:
            self.ready_future.set_exception(exc)

    def pause_writing(self):
        self._writing_paused = True
        if self._ready:
            self.protocol.pause_writing()

    def resume_writing(self):
        self._writing_paused = False
        if self._ready:
            self.protocol.resume_writing()

    def is_ready(self):
        return self._ready


class PGRawConn(asyncio.Transport):
    def __init__(self,
                 raw_transport: asyncio.Transport,
                 pg_state: PGState):
        super().__init__()
        self.raw_transport = raw_transport
        self._pg_state = pg_state

    @property
    def state(self):
        return self._pg_state

    def write(self, data: bytes):
        self.raw_transport.write(data)

    def close(self):
        if self.raw_transport:
            self.raw_transport.close()

    def is_closing(self):
        return self.raw_transport.is_closing()

    def get_extra_info(self, name: str, default=None):
        return self.raw_transport.get_extra_info(name, default)

    def pause_reading(self):
        self.raw_transport.pause_reading()

    def resume_reading(self):
        self.raw_transport.resume_reading()

    def is_reading(self):
        return self.raw_transport.is_reading()

    def __repr__(self):
        params = ', '.join(f"{k}={v}" for k, v in self._pg_state.parameters.items())
        auth_str = f", auth={self._pg_state.auth.name}" if self._pg_state.auth else ""
        raw_repr = repr(self.raw_transport)
        return f"<PGRawConn: connected{auth_str}, {params}, raw_connection={raw_repr}>"


class RustTransportUpdate(ConnectionStateUpdate):
    raw_transport: asyncio.Transport
    state: PyConnectionState
    state_change_callback: Optional[StateChangeCallback]

    def __init__(self,
                 state: PyConnectionState,
                 raw_transport: asyncio.Transport,
                 state_change_callback: Optional[StateChangeCallback]):
        self.state = state
        self.raw_transport = raw_transport
        self._state_change_callback = state_change_callback
        self._pg_state = PGState(parameters={}, cancellation_key=None, auth=None)

    def send(self, message: memoryview) -> None:
        self.raw_transport.write(bytes(message))

    def upgrade(self) -> None:
        asyncio.create_task(self._upgrade_to_ssl())

    async def _upgrade_to_ssl(self):
        sslmode, ssl_config = self.state.ssl_config
        sslmode = SSLMode.parse(sslmode.lower())
        ssl_context = _create_ssl(sslmode, ssl_config)
        loop = asyncio.get_running_loop()
        new_transport = await loop.start_tls(
            self.raw_transport,
            self.raw_transport.get_protocol(),
            ssl_context,
            server_side=False,
            ssl_handshake_timeout=None
        )
        self.raw_transport = new_transport
        self.state.drive_ssl_ready()

    def parameter(self, name: str, value: str) -> None:
        self._pg_state.parameters[name] = value

    def cancellation_key(self, pid: int, key: int) -> None:
        self._pg_state.cancellation_key = (pid, key)

    def state_changed(self, state: int) -> None:
        if self._state_change_callback is not None:
            self._state_change_callback(ConnectionStateType(state))

    def auth(self, auth: int) -> None:
        self._pg_state.auth = Authentication(auth)

async def _create_connection(protocol_factory: Callable[[],asyncio.Protocol],
                             host_candidates: List[Tuple[str, str, int]]) -> Tuple[asyncio.Transport, asyncio.Protocol]:
    e = None
    for protocol, host, port in host_candidates:
        try:
            if protocol == "unix":
                return await asyncio.get_running_loop().create_unix_connection(
                    protocol_factory,
                    host
                )
            else:
                return await asyncio.get_running_loop().create_connection(
                    protocol_factory,
                    host, port
                )
        except Exception as ex:
            e = ex
            continue
    raise ConnectionError("Failed to connect to any of the provided hosts", e)

async def create_postgres_connection(
    dsn: str,
    protocol_factory: Callable[[], asyncio.Protocol],
    *,
    state_change_callback: Optional[StateChangeCallback] = None
) -> Tuple[PGRawConn, asyncio.Protocol]:
    """
    Open a PostgreSQL connection to the address specified by the DSN.

    The DSN (Data Source Name) should include connection details like host, port, database, etc.

    protocol_factory must be a callable returning an asyncio protocol implementation.

    This method establishes the connection asynchronously. When successful, it returns a (PGRawConn, protocol) pair.

    :param dsn: Data Source Name for the PostgreSQL connection
    :param protocol_factory: Callable that returns an asyncio protocol
    :param state_change_callback: Optional callback for connection state changes
    :return: Tuple of PGRawConn and asyncio.Protocol
    """
    state = PyConnectionState(dsn, "postgres", "placeholder_home_dir")
    ready_future: asyncio.Future = asyncio.Future()

    user_protocol = protocol_factory()
    raw_transport, connect_protocol = await _create_connection(
        lambda: PGConnectionProtocol(state, user_protocol, ready_future),
        state.host_candidates
    )

    update = RustTransportUpdate(state, raw_transport, state_change_callback)
    state.update = update
    state.drive_initial()

    await ready_future

    raw_transport = update.raw_transport
    conn = PGRawConn(raw_transport, update._pg_state)
    raw_transport.set_protocol(user_protocol)

    # Notify the user protocol of successful connection
    user_protocol.connection_made(conn)

    return conn, user_protocol
