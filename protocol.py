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
    n_cadastros = 0
    n_clients = 0
    cond = True
    my_user = 'alguem'
    def return_users(self):
        return self.users
    #setando um dicionario pra controlar a votacao
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
        self.server.listen(1)
        os.system('clear')
        print('server on')
        self.generate_keys()
        self.create_dics()
        self.users = self.read_file()
        #self.user_votes = self.votes()

    def open_client(self, port):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_address = ('localhost', port)
        self.sock.connect(self.server_address)
        self.generate_keys()
    
    def server_wait_connection(self):
        self.client, self.client_address = self.server.accept()

        self.n_clients = self.n_clients + 1
        if self.n_clients > 5:
            self.cond = False

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

        return True
        
    def client_connection(self):

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
        
        return True

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

    def checa_login(self, usuario, senha):
        if self.users.get(usuario) == senha:
            return True
        else:
            return False

    def user_login_server(self):
        usuario = self.recv_hash(self.client)
        message = 'ok'
        self.send_hash(message, self.client)
        senha = self.recv_password(self.client)

        ret = self.checa_login(usuario, senha)

        if ret == False:
            message = 'false'
            self.send_hash(message, self.client)
        else:
            message = 'true'
            self.send_hash(message, self.client)
            self.my_user = usuario
        
        return ret

    def user_login_client(self, usuario, senha):
        self.send_hash(usuario, self.sock)
        ok = self.recv_hash(self.sock)

        self.send_password(senha, self.sock)
        ok = self.recv_hash(self.sock)
        if ok == 'true':
            return True 

        return False

    def cadastro_server(self):
        usuario = self.recv_hash(self.client)
        ok = 'ok'
        self.send_hash(ok, self.client)

        senha = self.recv_password(self.client)
        ok = 'ok'
        self.send_hash(ok, self.client)

        senha2 = self.recv_password(self.client)

        if senha != senha2:
            message = 'Senhas diferentes, tente novamente'
            self.send_hash(message, self.client)
            return False
        elif usuario in self.users: 
            message = 'Usuario ja cadastrado, tente novamente'
            self.send_hash(message, self.client)
            return False
        else:
            self.users[usuario] = senha
            message = 'Usuario cadastrado com sucesso!'
            self.send_hash(message, self.client) 
            return True          

    def cadastro_client(self, usuario, senha, senha2):
        self.send_hash(usuario, self.sock)
        ok = self.recv_hash(self.sock)

        self.send_password(senha, self.sock)
        ok = self.recv_hash(self.sock)

        self.send_password(senha2, self.sock)
        message = self.recv_hash(self.sock)

        if message == 'Usuario cadastrado com sucesso!':
            return True, message 
        
        return False, message

    def server_results(self):
        section = self.recv_hash(self.client)

        finish = True
        for users in self.users:
           if self.user_votes[section][users] == False:
                finish = False
                break
        if finish == True: 
            message = str(self.voting_sections[section])
            self.send_hash(message, self.client)
        else:
            message = 'Votacao ainda nao terminou'
            self.send_hash(message, self.client)

    def client_results(self, section):
        self.send_hash(section, self.sock)

        result = self.recv_hash(self.sock)
        return result

    def send_voting_sections(self):
        array = []
        for v in self.voting_sections:
            array.append(v)
        
        array = str(array)
        self.send_hash(array, self.client)
    
    def recv_voting_sections(self):
        array = self.recv_hash(self.sock)
        array = eval(array)

        return array

    def send_options(self):
        section = self.recv_hash(self.client)

        array = []
        if not section in self.voting_sections:
            array = str(array)
            self.send_hash(array, self.client)
            return False 
        
        for x in self.voting_sections[section]:
            array.append(x)
        
        array = str(array)
        self.send_hash(array, self.client)
        return True
    
    def recv_options(self, section):
        self.send_hash(section, self.sock)
        array = self.recv_hash(self.sock)
        array = eval(array)

        return array

    def client_vote(self, section, option):
        self.send_hash(section, self.sock)
        ok = self.recv_hash(self.sock)

        self.send_hash(option, self.sock)
        ok = self.recv_hash(self.sock)

        if ok == 'true':
            return True 
        return False

    def server_vote(self):
        section = self.recv_hash(self.client)
        ok = 'ok'
        self.send_hash(ok, self.client)

        option = self.recv_hash(self.client)
        if not section in self.voting_sections:
            ok = 'false'
            self.send_hash(ok, self.client)
            return False 
        if not option in self.voting_sections[section]:
            ok = 'false'
            self.send_hash(ok, self.client)
            return False
        if self.user_votes[section][self.my_user] == True:
            ok = 'false'
            self.send_hash(ok, self.client)
            return False 
            
        ok = 'true'
        self.send_hash(ok, self.client)
        self.voting_sections[section][option] = self.voting_sections[section][option] + 1
        self.user_votes[section][self.my_user] = True
        return True

    def server_create_session(self):
        name = self.recv_hash(self.client)
        ok = 'ok'
        self.send_hash(ok, self.client)

        options = self.recv_hash(self.client)
        options = eval(options)

        if name in self.voting_sections:
            message = 'false'
            self.send_hash(message, self.client)
            return False 
        else:
            self.voting_sections[name] = options

            #dic para a votacao daquela sessao
            self.user_votes[name] = {}
            self.user_votes[name] = self.votes()

            message = 'true'
            self.send_hash(message, self.client)
            return True
    
    def client_create_session(self, name, options):
        self.send_hash(name, self.sock)
        ok = self.recv_hash(self.sock)
        self.send_hash(str(options), self.sock)
        ok = self.recv_hash(self.sock)
        if ok == 'true':
            return True 
        return False
        
    def send_hash(self, message, sock):
        message = self.format_message(message)
        message = self.encrypt_symmetric(message)
        sock.sendall(message)
    
    def recv_hash(self, sock):
        message = sock.recv(4096)
        message = self.decrypt_symmetric(message)
        #essa func da erro aqui as vezes
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
