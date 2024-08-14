# Copyright (C) 2016-present MagicStack Inc. and the EdgeDB authors.
# Copyright (C) 2016-present the asyncpg authors and contributors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


from __future__ import annotations
from typing import Optional, Tuple, Union, Dict, List

import dataclasses
import enum
import getpass
import pathlib
import platform
import re
import ssl as ssl_module
import stat
import warnings
from . import _pg_rust

class SSLMode(enum.IntEnum):
    disable = 0
    allow = 1
    prefer = 2
    require = 3
    verify_ca = 4
    verify_full = 5

    @classmethod
    def parse(cls, sslmode: Union[SSLMode, str]) -> SSLMode:
        if isinstance(sslmode, SSLMode):
            rv = sslmode
        else:
            rv = getattr(cls, sslmode.replace('-', '_'))
        return rv


@dataclasses.dataclass
class ConnectionParameters:
    user: str
    password: Optional[str] = None
    database: Optional[str] = None
    ssl: Optional[ssl_module.SSLContext] = None
    sslmode: Optional[SSLMode] = None
    server_settings: Dict[str, str] = dataclasses.field(default_factory=dict)
    connect_timeout: Optional[int] = None


_system = platform.uname().system


if _system == 'Windows':
    import ctypes.wintypes

    CSIDL_APPDATA = 0x001a
    PGPASSFILE = 'pgpass.conf'

    def get_pg_home_directory() -> pathlib.Path:
        # We cannot simply use expanduser() as that returns the user's
        # home directory, whereas Postgres stores its config in
        # %AppData% on Windows.
        buf = ctypes.create_unicode_buffer(ctypes.wintypes.MAX_PATH)
        r = ctypes.windll.shell32.SHGetFolderPathW(  # type: ignore
            0, CSIDL_APPDATA, 0, 0, buf)
        if r:
            return pathlib.Path.home()
        else:
            return pathlib.Path(buf.value) / 'postgresql'
else:
    PGPASSFILE = '.pgpass'

    def get_pg_home_directory() -> pathlib.Path:
        return pathlib.Path.home() / '.postgresql'


def _read_password_file(passfile: pathlib.Path) -> List[Tuple[str, ...]]:

    passtab = []

    try:
        if not passfile.exists():
            return []

        if not passfile.is_file():
            warnings.warn(
                'password file {!r} is not a plain file'.format(passfile),
                stacklevel=4,
            )

            return []

        if _system != 'Windows':
            if passfile.stat().st_mode & (stat.S_IRWXG | stat.S_IRWXO):
                warnings.warn(
                    f'password file {passfile!r} has group or world access; '
                    'permissions should be u=rw (0600) or less',
                    stacklevel=4,
                )

                return []

        with passfile.open('rt') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    # Skip empty lines and comments.
                    continue
                # Backslash escapes both itself and the colon,
                # which is a record separator.
                line = line.replace(R'\\', '\n')
                passtab.append(tuple(
                    p.replace('\n', R'\\')
                    for p in re.split(r'(?<!\\):', line, maxsplit=4)
                ))
    except IOError:
        pass

    return passtab


def _read_password_from_pgpass(
    *,
    passfile: Optional[pathlib.Path],
    addrs: List[Tuple[str, int]],
    database: str,
    user: str,
) -> Optional[str]:
    """Parse the pgpass file and return the matching password.

    :return:
        Password string, if found, ``None`` otherwise.
    """

    if passfile is not None:
        passtab = _read_password_file(passfile)
        if not passtab:
            return None

    for host, port in addrs:
        if host.startswith('/'):
            # Unix sockets get normalized into 'localhost'
            host = 'localhost'

        for phost, pport, pdatabase, puser, ppassword in passtab:
            if phost != '*' and phost != host:
                continue
            if pport != '*' and pport != str(port):
                continue
            if pdatabase != '*' and pdatabase != database:
                continue
            if puser != '*' and puser != user:
                continue

            # Found a match.
            return ppassword

    return None


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


def _dot_postgresql_path(filename: str) -> str:
    return str((pathlib.Path.home() / '.postgresql' / filename).resolve())


def parse_dsn(
    dsn: str,
) -> Tuple[
    Tuple[Tuple[str, int], ...],
    ConnectionParameters,
]:
    try:
        parsed, ssl_paths = _pg_rust.parse_dsn(getpass.getuser(),
                                               str(get_pg_home_directory()),
                                               dsn)
    except Exception as e:
        raise ValueError(f"{e.args[0]}") from e

    ssl = None
    sslmode = SSLMode.disable
    ssl_config = parsed['ssl']
    if 'Enable' in ssl_config:
        ssl_config = ssl_config['Enable']
        ssl = ssl_module.SSLContext(ssl_module.PROTOCOL_TLS_CLIENT)
        sslmode = SSLMode.parse(ssl_config[0].lower())
        ssl.check_hostname = sslmode >= SSLMode.verify_full
        ssl_config = ssl_config[1]
        if sslmode < SSLMode.require:
            ssl.verify_mode = ssl_module.CERT_NONE
        else:
            if ssl_paths['rootcert']:
                ssl.load_verify_locations(ssl_paths['rootcert'])
                ssl.verify_mode = ssl_module.CERT_REQUIRED
            else:
                if sslmode == SSLMode.require:
                    ssl.verify_mode = ssl_module.CERT_NONE
            if ssl_paths['crl']:
                ssl.load_verify_locations(ssl_paths['crl'])
                ssl.verify_flags |= ssl_module.VERIFY_CRL_CHECK_CHAIN
        if ssl_paths['key'] and ssl_paths['cert']:
            ssl.load_cert_chain(ssl_paths['cert'],
                                ssl_paths['key'],
                                ssl_config['password'] or '')
        if ssl_config['max_protocol_version']:
            ssl.maximum_version = _parse_tls_version(
                ssl_config['max_protocol_version'])
        if ssl_config['min_protocol_version']:
            ssl.minimum_version = _parse_tls_version(
                ssl_config['min_protocol_version'])
    addrs: List[Tuple[str, int]] = []
    for host in parsed['hosts']:
        if 'Hostname' in host:
            host, port = host['Hostname']
            addrs.append((host, port))
        if 'IP' in host:
            hostname = host['IP'][0]
            # Reconstruct the scope ID
            if host['IP'][2]:
                hostname = f'{hostname}%{host['IP'][2]}'
            addrs.append((hostname, host['IP'][1]))
        elif 'Path' in host:
            path = host['Path']
            addrs.append((path, 5432))

    passfile: pathlib.Path | None = None
    password: str | None = ""
    password_config = parsed['password']
    if 'Unspecified' in password_config:
        passfile = get_pg_home_directory() / 'pgpass.conf'
    elif 'Passfile' in password_config:
        passfile = pathlib.Path(password_config['Passfile'])
    elif 'Specified' in password_config:
        password = password_config['Specified']

    database: str = str(parsed['database']) or ''
    user: str = str(parsed['user']) or ''
    if passfile:
        password = _read_password_from_pgpass(passfile=passfile,
                                              addrs=addrs,
                                              database=database,
                                              user=user)

    connect_timeout = parsed['connect_timeout']['secs'] \
        if parsed['connect_timeout'] else None
    params = ConnectionParameters(
        user=user,
        password=password,
        database=database,
        ssl=ssl,
        sslmode=sslmode,
        server_settings=parsed['server_settings'],
        connect_timeout=connect_timeout,
    )

    return tuple(addrs), params
