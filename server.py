from protocol import *
sock = Protocol()

sock.open_server(10000)


while sock.cond:
    sock.server_wait_connection()
    if sock.cond == False: 
        print("Limite de usuarios simultaneos excedido, o servidor ira fechar")
        arquivo = open("usuarios.txt", "w")
        for user in sock.users:
            arquivo.writelines(user + " " + sock.users[user] + "\n")
        arquivo.close()
