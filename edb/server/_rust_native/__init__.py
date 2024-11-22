from edb.server._rust_native.module import _conn_pool as conn_pool # noqa
from edb.server._rust_native.module import _pg_rust as pgrust # noqa
from edb.server._rust_native.module import create_to_python_channel

import weakref
import asyncio
_channels: weakref.WeakKeyDictionary = weakref.WeakKeyDictionary()

def get_thread_channel():
    loop = asyncio.get_running_loop()
    if channel := _channels.get(loop):
        return channel
    channel = create_to_python_channel()
    _channels[loop] = channel
    return channel

def init_async():
    pass
