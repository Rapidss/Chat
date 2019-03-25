import socket
import threading
import uuid
import random
import pickle
import hashlib
import getpass
import sys
import os
from Padding import appendPadding, removePadding
from Crypto.Cipher import AES
from cfg import SERVER, S_PORT, WELCOME

class Client():
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)	#Create the socket
	session_key = "" # Session key to decrypt the message key
	key = "" # key used to decrypt messages
	def __init__(self):
		self.s.connect((SERVER, S_PORT)) # connect to the server
		self.hwaddr = self.hash(hex(uuid.getnode())) # get HWADDR
		print(self.hwaddr)
		self.auth() # run auth with the server
		while 1:
			inc = self.s.recv(8192)
			out = pickle.loads(inc)
			if type(out) == str:
				if out == "HWADDR":
					print("HWID was not in preapproved list")
					self.shutdown()
				if out == "PASSWD":
					print("Password was incorrect, restart client")
					self.shutdown()
				if out == "AUTHED": # authorised
					self.key_exchange(self.s)
					print(self.session_key)
					print(self.key)
					print("Handshake completed successfully")
					t1 = threading.Thread(target = self.send) #create new thread used to send
					t1.daemon = True # deamon means terminate thread on program end
					t1.start() # start the new thread
			if not inc:
				break # connection lost
			elif type(out) != str: # message from another client
				ciphertext = out[0]
				padded_message = self.decrypt(self.key, ciphertext[0], ciphertext[1])
				print("{} : {}".format(out[1], padded_message.decode())) # display the message
		return 0
	def send(self):
		while 1:
			msg = input(">> ") # user input
			padded_msg = appendPadding(msg, blocksize=AES.block_size, mode="CMS") #pad input to blocksize
			tup = (self.hwaddr, self.encrypt(padded_msg, self.key)) # construct the tuple
			self.s.send(pickle.dumps(tup)) # construct the tuple

	def auth(self):
		passwd = getpass.getpass("Enter server password: ")
		tup = ("AUTH", self.hwaddr, self.hash(passwd)) # construct the tuple
		self.s.send(pickle.dumps(tup)) # construct the tuple
		return 0

	def key_exchange(self, s):
		"""Diffe-Hellman Key exchange"""
		incoming = s.recv(8192)
		incoming = pickle.loads(incoming)
		client_priv = random.randint(0, incoming[0]-1)
		client_pub = (incoming[1]^client_priv % incoming[0])
		s.send(pickle.dumps(client_pub))
		key = (incoming[2]^client_priv % incoming[0])
		self.session_key = self.key_hash(key) # creates session key to decrypt message key
		incoming = s.recv(8192)
		encrypted = pickle.loads(incoming)
		self.key = self.decrypt(self.session_key, encrypted[0], encrypted[1]) # the message key


	def decrypt(self, key, ciphertext, iv):
		"""A function to decrypt a message"""
		cipher = AES.new(key, AES.MODE_CBC, iv) # create a AES object
		return cipher.decrypt(ciphertext) # decrypt it

	def key_hash(self, x):
		"""A function to has keys"""
		x = str(x).encode()
		m = hashlib.md5()
		m.update(x)
		return m.hexdigest()

	def hash(self, x):
		"""hash function"""
		x = x.encode()
		m = hashlib.sha512()
		m.update(x)
		return m.hexdigest()

	def shutdown():
		self.s.close()

	def encrypt(self, plaintext, key):
		"""A function to encrypt messages"""
		iv = os.urandom(16) #creating an IV
		cipher = AES.new(key, AES.MODE_CBC, iv) # create a AES object
		ciphertext = cipher.encrypt(plaintext) # encrypt it
		return (ciphertext, iv)

print(WELCOME) # print welcome banner

try:
	client = Client()
except Exception as err:
	client.shutdown()
	sys.exit(err)