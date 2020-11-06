import socket
import sys
from Crypto import Random
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from binascii import hexlify
import base64

class Protocol:
    
    def open_server(self, port):
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_address = ('localhost', port)
        self.server.bind(self.server_address)
        self.server.listen(1)
        print('server on')

        self.generate_keys()

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
            print('recebi')
            message = self.decrypt_message(message)
            print(message)
            
            message = self.encrypt_message(message)
            self.client.sendall(message)
            print('mandei')

                
        finally:
            self.close_connection(self.client)
        
    def client_connection(self):
        try:
            print('conectou')

            self.sock_public_key = self.sock.recv(4096)
            self.sock_public_key = RSA.importKey(self.sock_public_key)
            self.create_cipher(self.sock_public_key)

            self.sock.sendall(self.public_key_str)

            message = raw_input('digita uma mensagem:')
            message = self.encrypt_message(message)
            self.sock.sendall(message)
            print('mandei')

            message = self.sock.recv(4096)
            print('recebi')
            message = self.decrypt_message(message)
            print(message)
            

        finally:
            print('closing socket')
            self.close_connection(self.sock)

    def close_connection(self, sock):
        sock.close()

    def generate_keys(self):
        self.private_key = RSA.generate(4096, Random.new().read)
        self.public_key = self.private_key.publickey()
        self.public_key_str = self.public_key.exportKey()
        self.decrypt = PKCS1_OAEP.new(key=self.private_key)
    
    def encrypt_message(self, message):
        return self.cipher.encrypt(message)

    def decrypt_message(self, message):
        return self.decrypt.decrypt(message)
    
    def create_cipher(self, public_key):
        self.cipher = PKCS1_OAEP.new(key=public_key)



