import socket
import sys
import hashlib
import os
import threading
import time
import pickle
import random
from Crypto.Util import number
from Crypto.Cipher import AES
from p import password, hwaddrs
from cfg import SERVER, S_PORT, N, G

class Server:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    clients = []
    auth_client = [] # authorised clients
    encrypt_key = os.urandom(16) # generate random encryption key # TODO: this should be change
    print(encrypt_key)
    def __init__(self):
        self.s.bind((SERVER, S_PORT)) # bind socket
        self.s.listen(1) # listen for incoming connections

    def handle_client(self, c, addr):
        """A function to handle clients"""
        print(c)
        while 1:
            inc = c.recv(8192)
            if not inc: # lost connection to the client
                    print("{} : {} has disconnected from the server".format(addr[0], addr[1]))
                    self.clients.remove(c)
                    c.close()
                    break
            if len(inc) > 0:
                message = pickle.loads(inc)
                print(message)
                if message[0] == "AUTH":
                    if message[2] == password:
                        if message[1] in hwaddrs:
                            self.clients.append(c)
                            tup = pickle.dumps("AUTHED")
                            c.send(tup) # authenticated
                            self.handshake(c) # start key handshake
                            self.auth_client.append(message[1]) #("AUTH", self.hwaddr, hash(passwd))
                            continue
                        elif message[1] not in hwaddrs: # not approved to connect
                            tup = pickle.dumps("HWADDR")
                            c.send(tup)
                            self.clients.remove(c)
                            c.close()
                            break
                    elif message[2] != password: #password was incorrect
                        tup = pickle.dumps("PASSWD")
                        c.send(tup)
                        print("<{} : {} : {}> got the password incorrect".format(message[0], addr[0], addr[1]))
                        self.clients.remove(c)
                        c.close()
                        break

                if message[0] in self.auth_client: # if they have completed the handshake
                    message = list(message)
                    message.append(hwaddrs[message[0]])
                    del message[0] # remove HWADDR
                    message = tuple(message)
                    out = pickle.dumps(message)         #(<message>, <sender>)
                    print(message)
                    for client in self.clients: # send the message to all current connections
                        client.send(out)
        return 0

    def encrypt(self, session_key):
        """A function to encrypt the key"""
        iv = os.urandom(16) # create a random IV
        cipher = AES.new(session_key, AES.MODE_CBC, iv) # new AES object
        ciphertext = cipher.encrypt(self.encrypt_key) #encrypt it
        return (ciphertext, iv) #return IV and ciphertext

    def handshake(self, c):
        """Diffe-Hellman Key exchange"""
        server_priv = random.randint(0, N-1)
        server_pub = (G^server_priv % N)
        tup = pickle.dumps((N, G, server_pub))
        time.sleep(1)
        c.send(tup)
        client_pub = c.recv(1024)
        if not client_pub:
            print("client conn dropped")
            return 0
        client_pub = pickle.loads(client_pub)
        key = (client_pub^server_priv % N)
        session_key = self.key_hash(key)
        del key
        x = self.encrypt(session_key)
        send_key = pickle.dumps(x)
        c.send(send_key)
        print("Handshake completed")

    def key_hash(self, x):
        x = str(x).encode()
        m = hashlib.md5()
        m.update(x)
        return m.hexdigest()

    def shutdown(err):
        self.s.close()
        sys.exit(err)

    def run(self):
        while 1:
            conn, addr = self.s.accept()
            t1 = threading.Thread(target = self.handle_client, args = (conn, addr)) # create a new thread for each client
            t1.daemon = True # deamon means terminate thread on program end
            t1.start() # start the thread

server = Server()

try:
    server.run()
except Exception as err:
    server.shutdown(err)