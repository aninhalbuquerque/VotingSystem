from protocol import *


sock = votingsys()
sock.open_server(10000)
sock.server_wait_connection()
