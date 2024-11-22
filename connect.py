from edb.server.pgcon.rust_transport import create_postgres_connection
import asyncio
import time

class MyProtocol(asyncio.Protocol):
    def __init__(self):
        self.closed = asyncio.Future()

    def connection_made(self, transport):
        self.transport = transport

    def data_received(self, data):
        print(f"Received: {data}")
        self.transport.close()

    def connection_lost(self, exc):
        print(f"Connection lost: {exc}")
        self.closed.set_result(None)

async def main():
    now = time.perf_counter_ns()
    transport, protocol = await create_postgres_connection(
        "postgres://user:password@localhost/postgres",
        lambda: MyProtocol(),
        state_change_callback=lambda state: print(f"Connection: {state.name}"))
    print(f"Connection time: {(time.perf_counter_ns() - now) // 1000}µs")
    print(f"Connected: {transport}")
    print(f"Peer: {transport.get_extra_info('peername')}")
    print(f"Cipher: {transport.get_extra_info('cipher')}")

    # Send a simple query message
    query = b'SELECT version();\0'
    message = b'Q' + (len(query) + 4).to_bytes(4, 'big') + query
    transport.write(message)

    await protocol.closed

asyncio.run(main())
