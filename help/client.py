import socket
import sys

# Create a TCP/IP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Connect the socket to the port where the server is listening
server_address = ('localhost', 10004)
print >>sys.stderr, 'connecting to %s port %s' % server_address
sock.connect(server_address)

def createVotingSection(sock):
    nome = sock.recv(100)
    print >>sys.stderr, nome
    nome = raw_input("->")
    sock.sendall(nome)
    qtOpcoes = sock.recv(1000)
    print >>sys.stderr, qtOpcoes
    qtOpcoes = raw_input("->")
    sock.sendall(qtOpcoes)
    x = int(qtOpcoes)
    for i in range(1, x + 1):
        opcao = sock.recv(100)
        print >>sys.stderr, opcao
        opcao = raw_input("->")
        sock.sendall(opcao)
    
    section = sock.recv(1000)
    print >>sys.stderr, section

def voting(sock):
    vote = sock.recv(100)
    print >>sys.stderr, vote
    sock.sendall("ok")
    while vote != "choose the section you would like to vote":
        vote = sock.recv(100)
        print >>sys.stderr, vote
        sock.sendall("ok")
    section = raw_input("->")
    sock.sendall(section)
    section = sock.recv(1000)
    print >>sys.stderr, section
    sock.sendall("ok")
    choose = sock.recv(1000)
    print >> sys.stderr, choose
    choose = raw_input("->")
    sock.sendall(choose)
    section = sock.recv(1000)
    print >>sys.stderr, section

def closeConnection(sock):
    sock.close()


try:
    menu = sock.recv(1000);
    print >>sys.stderr, menu
    choose = raw_input("->")
    sock.sendall(choose)
    resposta = sock.recv(1000);
    print >>sys.stderr, resposta
    while resposta != "Okay!" :
        choose = raw_input("->")
        sock.sendall(choose)
        resposta = sock.recv(1000);
        print >>sys.stderr, resposta
    sock.sendall(resposta)

    if choose == '1':
        createVotingSection(sock)
    elif choose == '2':
        voting(sock)


finally:
    print >>sys.stderr, 'closing socket'
    closeConnection(sock)