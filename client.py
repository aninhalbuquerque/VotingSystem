from protocol import *

sock = Protocol()

sock.open_client(10000)
sock.client_connection()

