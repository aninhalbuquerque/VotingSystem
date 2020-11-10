from protocol import *
import threading


def thread(sock, client):
    saiu = False
    ret = False 
    usuario = ''
    while not ret:
        choice = sock.recv_hash(client)
        if choice == '1':
            ok = False
            while not ok:
                ok, user = sock.user_login_server(client)

            ret = True
            usuario = user
        elif choice == '2':
            ok = False
            while not ok:
                ok = sock.cadastro_server(client)
        else: 
            sock.close_connection(client)
            ret = True
            saiu = True

    if not saiu:
        ret = False 
    while not ret:
        choice = sock.recv_hash(client)
        if choice == '1':
            sock.send_voting_sections(client)
            sock.send_options(client)
            sock.server_vote(client, usuario)
    
        elif choice == '2':
            sock.send_voting_sections(client)
            sock.server_results(client)

        elif choice == '3':
            ok = sock.server_create_session(client)
            while not ok:
                ok = sock.server_create_session(client)
        else:
            sock.close_connection(client)
            ret = True

    if sock.cond == False: 
        print("Limite de usuarios simultaneos excedido, o servidor ira fechar")
        arquivo = open("usuarios.txt", "w")
        for user in sock.users:
            arquivo.writelines(user + " " + sock.users[user] + "\n")
        arquivo.close()


sock = Protocol()
sock.open_server(10000)
threads = []

while sock.cond:
    client, client_address = sock.server_wait_connection()
    (ip, port) = client_address
    print('Connected to: ', ip)
    t = threading.Thread(target=thread, args=(sock, client))
    threads.append(t)
    t.start()
