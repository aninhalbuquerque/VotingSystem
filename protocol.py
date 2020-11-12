import socket
import sys
from Crypto import Random
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher import AES
from binascii import hexlify
import base64, os
import random
import string
import hashlib
import threading

class votingsys:
    n_cadastros = 0
    n_clients = 0
    cond = True

    def votes(self):
        my_dic = {}
        for user in self.users:
            my_dic[user] = False
        return my_dic
        
    def create_dics(self):
        self.users = {}
        # 'Voting Section 01' : {'Aninha':0, 'Day':0, 'Pucc4':0}
        self.voting_sections = {}
        #dic para a votacao
        self.user_votes = {}

    def open_server(self, port):
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_address = ('localhost', port)
        self.server.bind(self.server_address)
        self.server.listen(6)
        os.system('clear')
        print('server on')
        self.generate_keys()
        self.create_dics()
        self.users = self.read_file()
        self.mutex = threading.Lock()

    def open_client(self, port):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_address = ('localhost', port)
        self.sock.connect(self.server_address)
        self.generate_keys()
    
    def server_wait_connection(self):
        while self.cond:
            client, client_address = self.server.accept()
            t = threading.Thread(target=self.server_connection, args=(client,))
            t.start()
    
    def server_connection(self, client):

        #self.n_clients = self.n_clients + 1
        #if self.n_clients > 5:
            #self.cond = False

        client.sendall(self.public_key_str)

        client_public_key = client.recv(4096)
        client_public_key = RSA.importKey(client_public_key)
        cipher = self.create_cipher(client_public_key)

        message = client.recv(4096)
        #servidor decifra a mensagem com sua chave privada e cifra com a chave publica do cliente
        message = self.decrypt_message(message)
        message = self.encrypt_message(message, cipher)
        client.sendall(message)

        secret_key = self.generate_secret_key()
        encrypted_key = self.encrypt_message(secret_key, cipher)
        client.sendall(encrypted_key)

        self.server_login(client, secret_key)

        #return (client, client_address)
        
    def client_connection(self):

        sock_public_key = self.sock.recv(4096)
        sock_public_key = RSA.importKey(sock_public_key)
        cipher = self.create_cipher(sock_public_key)

        self.sock.sendall(self.public_key_str)

        #cliente manda mensagem cifrada com a chave publica do servidor
        message = self.random_message()
        message2 = self.encrypt_message(message, cipher)
        self.sock.sendall(message2)
        #cliente recebe mensagem e decifra com sua chave privada pra ver se ela eh a mesma
        message_recv = self.sock.recv(4096)
        message_recv = self.decrypt_message(message_recv)

        if(message != message_recv):
            print('servidor nao confiavel')
            self.close_connection(self.sock)
        
        encrypted_key = self.sock.recv(4096)
        secret_key = self.decrypt_message(encrypted_key)
        
        return secret_key

    def close_connection(self, sock):
        print('closing socket')
        sock.close()

    def write_clients(self):
        arquivo = open("usuarios.txt", "w")
        for user in self.users:
            arquivo.writelines(user + " " + self.users[user] + "\n")
        arquivo.close()

    def generate_keys(self):
        self.private_key = RSA.generate(4096, Random.new().read)
        self.public_key = self.private_key.publickey()
        self.public_key_str = self.public_key.exportKey()
        self.create_decipher(self.private_key)
    
    def encrypt_message(self, message, cipher):
        return cipher.encrypt(message)
    
    def decrypt_message(self, message):
        return self.decipher.decrypt(message)
    
    def create_cipher(self, public_key):
        #cifrar com a chave publica do outro
        return PKCS1_OAEP.new(key=public_key)
    
    def create_decipher(self, private_key):
        #decirar com sua chave privada
        self.decipher = PKCS1_OAEP.new(key=private_key)
    
    def random_message(self):
        tam = random.randrange(200)
        letters = string.ascii_letters
        message = ''.join(random.choice(letters) for i in range(tam))
        return message
    
    def generate_secret_key(self):
        return os.urandom(16)
    
    def encrypt_symmetric(self, message, secret_key):
        iv = Random.new().read(AES.block_size)
        padded_text = self.pad(message)
        cipher = AES.new(secret_key, AES.MODE_CBC, iv)
        dic = {
            'message': cipher.encrypt(padded_text),
            'iv' : iv
        }
        return str(dic)
        
    def decrypt_symmetric(self, message, secret_key):
        dic = eval(message)
        m = dic['message']
        iv = dic['iv']
        cipher = AES.new(secret_key, AES.MODE_CBC, iv)
        decrypted = cipher.decrypt(m)
        original = self.unpad(decrypted)
        return original
    
    def pad(self, message):
        block_size = 16
        remainder = len(message) % block_size
        padding_needed = block_size - remainder
        return message + padding_needed * ' '
    
    def unpad(self, message): 
        return message.rstrip()

    def server_login(self, client, secret_key):
        saiu = False
        ret = False 
        usuario = ''
        while not ret:
            choice = self.recv_hash(client, secret_key)
            if choice == '1':
                ok = False
                while not ok:
                    ok, user = self.user_login_server(client, secret_key)

                ret = True
                usuario = user
            elif choice == '2':
                ok = False
                while not ok:
                    ok = self.cadastro_server(client, secret_key)
            else: 
                self.write_clients()
                self.close_connection(client)
                ret = True
                saiu = True
        
        if not saiu:
            ret = False 
        while not ret:
            choice = self.recv_hash(client, secret_key)
            if choice == '1':
                self.send_voting_sections(client, secret_key)
                self.send_options(client, secret_key)
                self.server_vote(client, usuario, secret_key)
        
            elif choice == '2':
                self.send_voting_sections(client, secret_key)
                self.server_results(client, secret_key)

            elif choice == '3':
                ok = self.server_create_session(client, secret_key)
                while not ok:
                    ok = self.server_create_session(client, secret_key)
            else:
                self.write_clients()
                self.close_connection(client)
                ret = True

    def checa_login(self, usuario, senha):
        if self.users.get(usuario) == senha:
            return True
        else:
            return False

    def user_login_server(self, client, secret_key):
        usuario = self.recv_hash(client, secret_key)
        message = 'ok'
        self.send_hash(message, client, secret_key)
        senha = self.recv_password(client, secret_key)

        ret = self.checa_login(usuario, senha)

        if ret == False:
            message = 'false'
            self.send_hash(message, client, secret_key)
        else:
            message = 'true'
            self.send_hash(message, client, secret_key)
        
        return (ret, usuario)

    def user_login_client(self, usuario, senha, secret_key):
        self.send_hash(usuario, self.sock, secret_key)
        ok = self.recv_hash(self.sock, secret_key)

        self.send_password(senha, self.sock, secret_key)
        ok = self.recv_hash(self.sock, secret_key)
        if ok == 'true':
            return True 

        return False

    def cadastro_server(self, client, secret_key):
        usuario = self.recv_hash(client, secret_key)
        ok = 'ok'
        self.send_hash(ok, client, secret_key)

        senha = self.recv_password(client, secret_key)
        ok = 'ok'
        self.send_hash(ok, client, secret_key)

        senha2 = self.recv_password(client, secret_key)

        if senha != senha2:
            message = 'Senhas diferentes. Tente novamente:'
            self.send_hash(message, client, secret_key)
            return False
        elif usuario in self.users: 
            message = 'Usuario ja cadastrado. Tente novamente:'
            self.send_hash(message, client, secret_key)
            return False
        else:
            with self.mutex: 
                self.users[usuario] = senha
            message = 'Usuario cadastrado com sucesso!'
            self.send_hash(message, client, secret_key) 
            return True          

    def cadastro_client(self, usuario, senha, senha2, secret_key):
        self.send_hash(usuario, self.sock, secret_key)
        ok = self.recv_hash(self.sock, secret_key)

        self.send_password(senha, self.sock, secret_key)
        ok = self.recv_hash(self.sock, secret_key)

        self.send_password(senha2, self.sock, secret_key)
        message = self.recv_hash(self.sock, secret_key)

        if message == 'Usuario cadastrado com sucesso!':
            return True, message 
        
        return False, message

    def server_results(self, client, secret_key):
        section = self.recv_hash(client, secret_key)
        if not section in self.voting_sections:
            message = 'Essa sessao nao existe'
            self.send_hash(message, client, secret_key)
        else:
            finish = True
            for users in self.users:
                if not users in self.user_votes[section] or self.user_votes[section][users] == False:
                    finish = False
                    break  
            
            if finish == True: 
                message = str(self.voting_sections[section])
                self.send_hash(message, client, secret_key)
            else:
                message = 'Votacao ainda nao terminou'
                self.send_hash(message, client, secret_key)

    def client_results(self, section, secret_key):
        self.send_hash(section, self.sock, secret_key)

        result = self.recv_hash(self.sock, secret_key)
        if result == 'Votacao ainda nao terminou' or result == 'Essa sessao nao existe':
            return (False, result)
        return (True, result)

    def send_voting_sections(self, client, secret_key):
        array = []
        for v in self.voting_sections:
            array.append(v)
        
        array = str(array)
        self.send_hash(array, client, secret_key)
    
    def recv_voting_sections(self, secret_key):
        array = self.recv_hash(self.sock, secret_key)
        array = eval(array)

        return array

    def send_options(self, client, secret_key):
        section = self.recv_hash(client, secret_key)

        array = []
        if not section in self.voting_sections:
            array = str(array)
            self.send_hash(array, client, secret_key)
            return False 
        
        for x in self.voting_sections[section]:
            array.append(x)
        
        array = str(array)
        self.send_hash(array, client, secret_key)
        return True
    
    def recv_options(self, section, secret_key):
        self.send_hash(section, self.sock, secret_key)
        array = self.recv_hash(self.sock, secret_key)
        array = eval(array)

        return array

    def client_vote(self, section, option, secret_key):
        self.send_hash(section, self.sock, secret_key)
        ok = self.recv_hash(self.sock, secret_key)

        self.send_hash(option, self.sock, secret_key)
        ok = self.recv_hash(self.sock, secret_key)

        if ok == 'true':
            return (True, ok) 
        return (False, ok)

    def server_vote(self, client, my_user, secret_key):
        section = self.recv_hash(client, secret_key)
        ok = 'ok'
        self.send_hash(ok, client, secret_key)

        option = self.recv_hash(client, secret_key)
        if not section in self.voting_sections:
            ok = 'Essa sessao nao exite'
            self.send_hash(ok, client, secret_key)
            return False 
        if not option in self.voting_sections[section]:
            ok = 'Essa opcao nao existe nessa sessao'
            self.send_hash(ok, client, secret_key)
            return False
        if my_user in self.user_votes[section] and self.user_votes[section][my_user] == True:
            ok = 'Usuario ja votou nessa sessao'
            self.send_hash(ok, client, secret_key)
            return False 
            
        ok = 'true'
        self.send_hash(ok, client, secret_key)
        with self.mutex:
            self.voting_sections[section][option] = self.voting_sections[section][option] + 1
            self.user_votes[section][my_user] = True
        
        return True

    def server_create_session(self, client, secret_key):
        name = self.recv_hash(client, secret_key)
        ok = 'ok'
        self.send_hash(ok, client, secret_key)

        options = self.recv_hash(client, secret_key)
        options = eval(options)

        if name in self.voting_sections:
            message = 'false'
            self.send_hash(message, client, secret_key)
            return False 
        else:
            with self.mutex:
                self.voting_sections[name] = options

                #dic para a votacao daquela sessao
                self.user_votes[name] = {}
                self.user_votes[name] = self.votes()

            message = 'true'
            self.send_hash(message, client, secret_key)
            return True
    
    def client_create_session(self, name, options, secret_key):
        self.send_hash(name, self.sock, secret_key)
        ok = self.recv_hash(self.sock, secret_key)
        self.send_hash(str(options), self.sock, secret_key)
        ok = self.recv_hash(self.sock, secret_key)
        if ok == 'true':
            return True 
        return False
        
    def send_hash(self, message, sock, secret_key):
        message = self.format_message(message)
        message = self.encrypt_symmetric(message, secret_key)
        sock.sendall(message)
    
    def recv_hash(self, sock, secret_key):
        message = sock.recv(4096)
        message = self.decrypt_symmetric(message, secret_key)
        #essa func da erro aqui as vezes
        message = eval(message)
        if not self.compare_message(message):
            print('servidor nao confiavel')
            self.close_connection(sock)
        
        return message['message']
       
    def send_password(self, password, sock, secret_key):
        password = hashlib.sha256(password).hexdigest()
        #print(password)
        password = self.encrypt_symmetric(password, secret_key)
        sock.sendall(password)
    
    def recv_password(self, sock, secret_key):
        password = sock.recv(4096)
        password = self.decrypt_symmetric(password, secret_key)
        return password

    def format_message(self, message):
        hashed = hashlib.sha256(message).hexdigest()
        dic = {
            'message' : message,
            'hashed' : hashed 
        }
        return str(dic)
    
    def compare_message(self, dic):
        m = hashlib.sha256(dic['message']).hexdigest()
        hashed = dic['hashed']
        return m == hashed
    
    def read_file(self):

        lista_users = []
        arquivo = open("usuarios.txt", "r")
        lista_users = arquivo.readlines()
        arquivo.close()
        my_dic = {}
        for users in lista_users:
            user_aux = users.split(" ")
            length = len(user_aux[1])
            user_name = user_aux[0]
            password = user_aux[1]
            password = password[0:(length-1)]
            my_dic[user_name] = password
            self.n_cadastros = self.n_cadastros + 1


        return my_dic
