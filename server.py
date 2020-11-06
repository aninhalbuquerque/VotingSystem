from protocol import *

sock = Protocol()

sock.open_server(10000)

while True:
    sock.server_wait_connection()