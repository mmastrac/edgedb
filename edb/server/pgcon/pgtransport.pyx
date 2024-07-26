#
# This source file is part of the EdgeDB open source project.
#
# Copyright 2016-present MagicStack Inc. and the EdgeDB authors.
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
#

cimport cython
cimport cpython

@cython.final
cdef class PGTransport:
    def connection_made(self, transport):
        if self.transport is not None:
            raise RuntimeError('connection_made: invalid connection status')
        self.transport = transport
        self.connected_fut.set_result(True)
        self.connected_fut = None

    def connection_lost(self, exc):
        # Mark the connection as disconnected, so that `self.is_healthy()`
        # surely returns False for this connection.
        self.connected = False

        self.transport = None

        if self.pinned_by is not None:
            pinned_by = self.pinned_by
            self.pinned_by = None
            pinned_by.on_aborted_pgcon(self)

        if self.is_system_db:
            self.tenant.on_sys_pgcon_connection_lost(exc)
        elif self.tenant is not None:
            if not self.close_requested:
                self.tenant.on_pgcon_broken()
            else:
                self.tenant.on_pgcon_lost()

        if self.connected_fut is not None and not self.connected_fut.done():
            self.connected_fut.set_exception(ConnectionAbortedError())
            return

        if self.msg_waiter is not None and not self.msg_waiter.done():
            self.msg_waiter.set_exception(ConnectionAbortedError())
            self.msg_waiter = None

    def pause_writing(self):
        pass

    def resume_writing(self):
        pass

    def data_received(self, data):
        self.buffer.feed_data(data)

        if self.connected and self.idle:
            assert self.msg_waiter is None
            self.fallthrough_idle()

        elif (self.msg_waiter is not None and
                self.buffer.take_message() and
                not self.msg_waiter.cancelled()):
            self.msg_waiter.set_result(True)
            self.msg_waiter = None

    def eof_received(self):
        pass

    cdef write(self, buf):
        pass

    cdef wait_for_message(self):
        return self._wait_for_message(self)

    async def _wait_for_message(self):
        if self.buffer.take_message():
            return
        if self.transport is None:
            raise ConnectionAbortedError()
        self.msg_waiter = self.loop.create_future()
        await self.msg_waiter
        return self.buffer.get_message_type()
