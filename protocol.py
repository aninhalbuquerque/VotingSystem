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

class Protocol:
    
    def create_dics(self):
        # 'alas3' : {'nome': 'Ana Albuquerque', 'senha': 'senhacodificada'}
        self.users = {'aninha' : hashlib.sha256('linda').hexdigest()}
        # 'Voting Section 01' : {'Aninha':0, 'Day':0, 'Pucc4':0}
        self.voting_sections = {}

    def open_server(self, port):
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_address = ('localhost', port)
        self.server.bind(self.server_address)
        self.server.listen(1)
        os.system('clear')
        print('server on')
        self.generate_keys()
        self.create_dics()

    def open_client(self, port):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_address = ('localhost', port)
        self.sock.connect(self.server_address)

        self.generate_keys()
    
    def server_wait_connection(self):
        self.client, self.client_address = self.server.accept()

        try:
            print('conectou')

            self.client.sendall(self.public_key_str)

            self.client_public_key = self.client.recv(4096)
            self.client_public_key = RSA.importKey(self.client_public_key)
            self.create_cipher(self.client_public_key)

            message = self.client.recv(4096)
            #servidor decifra a mensagem com sua chave privada e cifra com a chave publica do cliente
            message = self.decrypt_message(message)
            message = self.encrypt_message(message)
            self.client.sendall(message)

            self.secret_key = self.generate_secret_key()
            encrypted_key = self.encrypt_message(self.secret_key)
            self.client.sendall(encrypted_key)

            okay = self.client.recv(4096)

            self.server_login()


                
        finally:
            self.close_connection(self.client)
            #self.close_connection(self.server)
        
    def client_connection(self):
        try:
            print('conectou')

            self.sock_public_key = self.sock.recv(4096)
            self.sock_public_key = RSA.importKey(self.sock_public_key)
            self.create_cipher(self.sock_public_key)

            self.sock.sendall(self.public_key_str)

            #cliente manda mensagem cifrada com a chave publica do servidor
            message = self.random_message()
            message2 = self.encrypt_message(message)
            self.sock.sendall(message2)
            #cliente recebe mensagem e decifra com sua chave privada pra ver se ela eh a mesma
            message_recv = self.sock.recv(4096)
            message_recv = self.decrypt_message(message_recv)

            if(message != message_recv):
                print('servidor nao confiavel')
                self.close_connection(self.sock)
            
            encrypted_key = self.sock.recv(4096)
            self.secret_key = self.decrypt_message(encrypted_key)

            self.sock.sendall('okay')

            self.client_login()

        finally:
            self.close_connection(self.sock)

    def close_connection(self, sock):
        print('closing socket')
        sock.close()

    def generate_keys(self):
        self.private_key = RSA.generate(4096, Random.new().read)
        self.public_key = self.private_key.publickey()
        self.public_key_str = self.public_key.exportKey()
        self.create_decipher(self.private_key)
    
    def encrypt_message(self, message):
        return self.cipher.encrypt(message)
    
    def decrypt_message(self, message):
        return self.decipher.decrypt(message)
    
    def create_cipher(self, public_key):
        #cifrar com a chave publica do outro
        self.cipher = PKCS1_OAEP.new(key=public_key)
    
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
    
    def encrypt_symmetric(self, message):
        iv = Random.new().read(AES.block_size)
        padded_text = self.pad(message)
        cipher = AES.new(self.secret_key, AES.MODE_CBC, iv)
        dic = {
            'message': cipher.encrypt(padded_text),
            'iv' : iv
        }
        return str(dic)
        
    def decrypt_symmetric(self, message):
        dic = eval(message)
        m = dic['message']
        iv = dic['iv']
        cipher = AES.new(self.secret_key, AES.MODE_CBC, iv)
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
    
    def server_login(self):
        ret = False 

        while not ret:
            menu = 'Digite a opcao desejada:\n1.Fazer login\n2.Cadastrar usuario\n'
            self.send_hash(menu, self.client)

            choice = self.recv_hash(self.client)
            while choice != '1' and choice != '2':
                erro = 'Entrada invalida, tente novamente.'
                self.send_hash(erro, self.client)
                choice = self.recv_hash(self.client)
            
            if choice == '1':
                message = 'user quer fazer login'
                print(message)

                message = 'okay'
                self.send_hash(message, self.client)

                self.user_login_server()

                ret = True
            else:
                message = 'user quer se cadastrar'
                print(message)
                message = 'okay'
                self.send_hash(message, self.client)
                
                self.cadastro_server()
  
    def client_login(self):
        ret = False

        while not ret:
            os.system('clear')
            menu = self.recv_hash(self.sock)
            print(menu)

            choice = raw_input('->')
            self.send_hash(choice, self.sock)
            answer = self.recv_hash(self.sock)
            while answer == 'Entrada invalida, tente novamente.':
                print(answer)
                choice = raw_input('->')
                self.send_hash(choice, self.sock)
                answer = self.recv_hash(self.sock)

            if choice == '1':
                self.user_login_client()
                ret = True
            else:
                self.cadastro_client()

    def checa_login(self, usuario, senha):
        if self.users.get(usuario) == senha:
            return True
        else:
            return False

    def user_login_server(self):
        ret = False
        message = 'por favor, entre com seu usuario.'
        self.send_hash(message, self.client)

        while ret == False:

            usuario = self.recv_hash(self.client)

            message = 'por favor, entre com sua senha.'
            self.send_hash(message, self.client)
            senha = self.recv_password(self.client)

            ret = self.checa_login(usuario, senha)

            if ret == False:
                message = 'Usuario ou senha invalidos. Tente novamente, entre com seu usuario.'
                self.send_hash(message, self.client)
            else:
                message = 'login realizado com sucesso!'
                self.send_hash(message, self.client)

        okay = self.recv_hash(self.client)
        if okay != 'okay':
            self.close_connection(self.client)
        
        message = 'Digite a opcao desejada:\n1. votar.\n2. checar resultados.\n3. criar sessao de voto.'
        self.send_hash(message, self.client)

        choice = self.recv_hash(self.client)

        while choice != '1' and choice != '2' and choice != '3':
            erro = 'Entrada invalida, tente novamente.'
            self.send_hash(erro, self.client)
            choice = self.recv_hash(self.client)

        message = 'okay'
        self.send_hash(message, self.client)

        '''if choice == '1':
            #self.server_vote()
        elif choice == '2':
            #self.server_results()
        else:
            #self.server_create_session()'''

    def user_login_client(self):
        os.system('clear')

        message = self.recv_hash(self.sock)
        print(message)
        usuario = raw_input('->')
        self.send_hash(usuario, self.sock)

        message = self.recv_hash(self.sock)
        print(message)
        senha = raw_input('->')
        self.send_password(senha, self.sock)

        message = self.recv_hash(self.sock)
        while message != 'login realizado com sucesso!':
            print(message)
            usuario = raw_input('->')
            self.send_hash(usuario, self.sock)

            message = self.recv_hash(self.sock)
            print(message)
            senha = raw_input('->')
            self.send_password(senha, self.sock)
            message = self.recv_hash(self.sock)

        print(message)

        message = 'okay'
        self.send_hash(message, self.sock)

        message = self.recv_hash(self.sock)
        print(message)

        choice = raw_input('->')
        self.send_hash(choice, self.sock)
        recv = self.recv_hash(self.sock)
        while recv == 'Entrada invalida, tente novamente.':
            print(recv)
            choice = raw_input('->')
            self.send_hash(choice, self.sock)
            recv = self.recv_hash(self.sock)
        
        self.close_connection(self.sock)

        '''if choice == '1':
            #self.client_vote()
        elif choice == '2':
            #self.client_results()
        else:
            #self.client_create_session()'''

    def cadastro_server(self):

        ret = False 
        
        while not ret:
            message = 'Por favor, entre com o usuario que deseja cadastrar: '
            self.send_hash(message, self.client)
            usuario = self.recv_hash(self.client)

            message = 'Por favor, entre com a senha: '
            self.send_hash(message, self.client)
            senha = self.recv_password(self.client)
            #print(senha)

            message = 'Por favor, repita a senha: '
            self.send_hash(message, self.client)
            senha2 = self.recv_password(self.client)

            if senha != senha2:
                message = 'Senhas diferentes, tente novamente'
                self.send_hash(message, self.client)
            elif usuario in self.users: 
                message = 'Usuario ja cadastrado, tente novamente'
                self.send_hash(message, self.client)
            else:
                ret = True
                self.users[usuario] = senha
                message = 'Usuario cadastrado com sucesso!'
                self.send_hash(message, self.client)           

    def cadastro_client(self):
        os.system('clear')

        ret = False 

        while not ret:
            message = self.recv_hash(self.sock)
            print(message)
            usuario = raw_input('->')
            usuario_hash = hashlib.sha256(usuario).hexdigest()
            self.send_hash(usuario, self.sock)

            message = self.recv_hash(self.sock)
            print(message)
            senha = raw_input('->')
            self.send_password(senha, self.sock)

            message = self.recv_hash(self.sock)
            print(message)
            senha2 = raw_input('->')
            self.send_password(senha2, self.sock)

            message = self.recv_hash(self.sock)
            print(message)

            if message == 'Usuario cadastrado com sucesso!':
                ret = True
    
    def send_hash(self, message, sock):
        message = self.format_message(message)
        message = self.encrypt_symmetric(message)
        sock.sendall(message)
    
    def recv_hash(self, sock):
        message = sock.recv(4096)
        message = self.decrypt_symmetric(message)
        message = eval(message)
        if not self.compare_message(message):
            print('servidor nao confiavel')
            self.close_connection(sock)
        
        return message['message']
    
    def send_password(self, password, sock):
        password = hashlib.sha256(password).hexdigest()
        #print(password)
        password = self.encrypt_symmetric(password)
        sock.sendall(password)
    
    def recv_password(self, sock):
        password = sock.recv(4096)
        password = self.decrypt_symmetric(password)
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
