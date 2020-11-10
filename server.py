from protocol import *
sock = Protocol()

sock.open_server(10000)

while sock.cond:
    sock.server_wait_connection()
    
    saiu = False
    ret = False 
    while not ret:
        choice = sock.recv_hash(sock.client)
        if choice == '1':
            ok = False
            while not ok:
                ok = sock.user_login_server()
            
            ret = True
        elif choice == '2':
            ok = False
            while not ok:
                ok = sock.cadastro_server()
        else: 
            sock.close_connection(sock.client)
            ret = True
            saiu = True

    if not saiu:
        ret = False 
    while not ret:
        choice = sock.recv_hash(sock.client)
        if choice == '1':
            sock.send_voting_sections()
            sock.send_options()
            sock.server_vote()
    
        elif choice == '2':
            sock.send_voting_sections()
            sock.server_results()

        elif choice == '3':
            ok = sock.server_create_session()
            while not ok:
                ok = sock.server_create_session()
        else:
            sock.close_connection(sock.client)
            ret = True

    if sock.cond == False: 
        print("Limite de usuarios simultaneos excedido, o servidor ira fechar")
        arquivo = open("usuarios.txt", "w")
        for user in sock.users:
            arquivo.writelines(user + " " + sock.users[user] + "\n")
        arquivo.close()
