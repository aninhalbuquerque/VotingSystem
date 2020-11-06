import socket
import sys

# Create a TCP/IP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# Bind the socket to the port
server_address = ('localhost', 10004)
print >>sys.stderr, 'starting up on %s port %s' % server_address
sock.bind(server_address)
# Listen for incoming connections
sock.listen(1)

votingSections = {"Voting Section 01" : {"Aninha":0, "Day":0, "Pucc4":0}}
qtVotingSections = 0

def createVotingSection(client):
    global votingSections
    global qtVotingSections
    if qtVotingSections == 100:
        erro = "we have too many voting sections already"
        client.sendall(erro)
        closeConnection(client)
    else:
        nome = "tell me a title for your voting section (1-100)"
        client.sendall(nome)
        nome = client.recv(100)
        votingSections[nome] = []
        qtOpcoes = "tell how many voting options you want in your voting section (1-9)"
        client.sendall(qtOpcoes)
        qtOpcoes = client.recv(1)
        x = int(qtOpcoes)
        for i in range(1, x + 1):
            opcao = "tell me the option number " + str(i) + " (1-10)"
            client.sendall(opcao)
            opcao = client.recv(100)
            votingSections[nome].append({opcao:0})
        client.sendall(str(votingSections[nome]))
        qtVotingSections = qtVotingSections + 1
        closeConnection(client)

def voting(client):
    vote = "those are the open voting sections:"
    client.sendall(vote)
    ok = client.recv(2)
    for i in votingSections:
        client.sendall("  - " + i)
        ok = client.recv(2)
    vote = "choose the section you would like to vote"
    client.sendall(vote)
    ok = client.recv(2)
    section = client.recv(1000)
    print >>sys.stderr, section
    if section in votingSections:
        options = str(votingSections[section])
        client.sendall(options)
        ok = client.recv(2)
        vote = "choose the option you would like to vote"
        client.sendall(vote)
        vote = client.recv(100)
        print >>sys.stderr, section, vote
        if vote in votingSections[section]: 
            votingSections[section][vote] = votingSections[section][vote] + 1
            options = str(votingSections[section])
            client.sendall(options)
        else:
            options = "this option doesn't exist"
            client.sendall(options)
        
        
    else:
        section = "this section doesn't exist"
        client.sendall(section)


def closeConnection(client):
    client.close()


while True:
    # Wait for a connection
    print >>sys.stderr, 'waiting for a connection'
    client, client_address = sock.accept()

    try:
        print >>sys.stderr, 'connection from', client_address
        menu = "Voting System\n\nChoose one action below:\n1.Create a voting section.\n2.Vote in a voting section.\n3.Check who won.\n"
        client.sendall(menu)

        choose = client.recv(1000)
        print >>sys.stderr, 'the choise was', choose

        while choose != '1' and choose != '2' and choose != '3':
            erro = "Entrada invalida, tente novamente."
            client.sendall(erro)
            choose = client.recv(1000)
            print >>sys.stderr, 'the choise was', choose
        
        pegou = "Okay!"
        client.sendall(pegou)
        pegou = client.recv(10)

        if choose == '1':
            createVotingSection(client)
        elif choose == '2':
            voting(client)

            
    finally:
        # Clean up the connection
        closeConnection(client)