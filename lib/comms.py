import struct
from Crypto.Hash import SHA256
from Crypto.Hash import HMAC
from Crypto import Random
from Crypto.Random import random
from Crypto.Cipher import XOR
from Crypto.Cipher import AES
from dh import create_dh_key, calculate_dh_secret

class StealthConn(object):
  def __init__(self, conn, client=False, server=False, verbose=True):
    self.conn               = conn
    self.client             = client
    self.server             = server
    self.verbose            = verbose    
    # Note that all variables below are stored in byte format
    self.session_nonce_hash = None
    self.my_private_key     = None
    self.their_public_key   = None
    self.shared_hash        = None
    
    self.initiate_session()

  def __print_verbose(self, string):
    if self.verbose:
      print(string)
   
  def __packet_send(self, data):
    """ 
    Sends data in a 'packet'.
    """
    # Encode the data's length into an unsigned two byte int ('H')
    pkt_len = struct.pack('H', len(data))
    self.conn.sendall(pkt_len)
    self.conn.sendall(data)

  def __packet_recv(self):
    """ 
    Recieves a packet from the network.
    Returns data and length of the data.
    """
    pkt_len_packed = self.conn.recv(struct.calcsize('H'))
    pkt_len = struct.unpack('H', pkt_len_packed)[0]
    
    return self.conn.recv(pkt_len), pkt_len

  def __sync_session_nonces(self, shared_hash):
    """
    Used to generate and synchronise nonces between
    client and server. This is used to prevent relplay
    attacks.
    """
    if self.server:
      # Generate the pseudorandom server nonce & send to client
      snonce = bytes(str(random.randint(1, 2**4096)), "ascii")
      self.__packet_send(snonce)
      
      # Recieve the session_nonce_hash from the client
      self.session_nonce_hash, pkt_len = self.__packet_recv()
      self.__print_verbose("Shared session nonce (server): {0}".format(self.session_nonce_hash))
      
      
    if self.client:
      # Generate the pseudorandom client nonce and recieve the server nonce
      cnonce = bytes(str(random.randint(1, 2**4096)), "ascii") # The client nonce is kept secret and thrown away afterwards
      snonce, pkt_len = self.__packet_recv()

      # Calculate the session nonces with shared secret hash
      calculated_nonce = snonce + cnonce + shared_hash
      self.session_nonce_hash = str.encode(SHA256.new(bytes(calculated_nonce)).hexdigest())
      
      # Encode the string to bytes for transmission and send
      self.__packet_send(self.session_nonce_hash)
      self.__print_verbose("Shared session nonce (client): {0}".format(self.session_nonce_hash))
    
  def initiate_session(self):
    """
    Initiates session between client and server bots.
    """
    # Perform the initial connection handshake for agreeing on a shared secret
    # This can be broken into code run just on the server or just on the client
    if self.server or self.client:
      my_public_key, self.my_private_key = create_dh_key()

      # Send them our public key
      self.__packet_send(bytes(str(my_public_key), "ascii"))

      # Receive their public key - Used in Cipher as encryption key
      pubKey, key_len = self.__packet_recv()
      self.their_public_key = int(pubKey)

      # Obtain our shared secret
      self.shared_hash = calculate_dh_secret(self.their_public_key, self.my_private_key)
      self.shared_hash = bytes(self.shared_hash, "ascii")
      print("Shared hash: {}".format(self.shared_hash))
       
      self.__sync_session_nonces(self.shared_hash)

      # Initialize the encrypt and decrypt Ciphers
      iv = Random.OSRNG.posix.new().read(AES.block_size) #TODO: Generate on the fly
        	
      # Default XOR algorithm can only take a key of length 32  
      ## XOR.new(shared_hash[:4]) # cipher = AES.new(their_public_key, AES.MODE_OFB, iv)
      ## XOR.new(shared_hash[:4]) # cipher = AES.new(our_private_key, AES.MODE_OFB, iv)
	
      #Implement AES cipher - TODO: TEST CODE
      bTheir_pub = bytes(str(self.their_public_key), "ascii")
      bMy_priv = bytes(str(self.my_private_key), "ascii")
      
      self.encryptCipher = AES.new(bTheir_pub.ljust(32)[:32], AES.MODE_OFB, iv)
      self.decryptCipher = AES.new(bMy_priv.ljust(32)[:32], AES.MODE_OFB, iv) 

  def send(self, data):
    """
    Encrypt and send data over the network.
    """
    # Initialise the encrypt Cipher
    iv = Random.OSRNG.posix.new().read(AES.block_size)
    bTheir_pub = bytes(str(self.their_public_key), "ascii")
    cipher = AES.new(bTheir_pub.ljust(32)[:32], AES.MODE_OFB, iv)
    
    # Record the original len of the data, and pad message out
    # to a multiple of 16 for transmission.
    self.__print_verbose("Original data: {}".format(data))
    data_size = len(data)
    if len(data) % 16 != 0:
      data += b' ' * (16 - len(data) % 16)
      
    
    # Encrypt the data
    encrypted_data = cipher.encrypt(data)
    self.__print_verbose("Encrypted data: {}".format(repr(encrypted_data)))
    self.__print_verbose("Sending packet of length {}".format(len(encrypted_data)))
    
	  # Create the HMAC
    hmac = HMAC.new(self.shared_hash, digestmod=SHA256)
    hmac.update(encrypted_data)
    
    # Encode information so its in byte format
    hmac = bytes(str(hmac.hexdigest()), "ascii")
    data_size = bytes(str(data_size), "ascii")
    
    # Send the encrypted data with relevant information
    self.__packet_send(self.session_nonce_hash) # Send the session nonce (for Anti-Replay attacks)
    self.__packet_send(iv)                      # Send the iv (to create the decrypt cipher)
    self.__packet_send(data_size)               # Send the length of the data
    self.__packet_send(encrypted_data)          # Send the encrypted data
    self.__packet_send(hmac)                    # Send the hmac
	  
	
  def recv(self):
    """
    Recieve and decrypt data from the network.
    """
    # Recieve the encrypted data with relevant information
    snh, pkt_len                = self.__packet_recv() # The session nonce hash
    iv, pkt_len                 = self.__packet_recv() # The iv used in encryption
    origdata_len, pkt_len       = self.__packet_recv() # The size of the original data
    encrypted_data, encrypt_len = self.__packet_recv() # The encrypted data
    hmac, pkt_len               = self.__packet_recv() # The hashed Message Authentication Code
    
    # Initialize decrypt cipher
    bMy_priv = bytes(str(self.my_private_key), "ascii")
    cipher = AES.new(bMy_priv.ljust(32)[:32], AES.MODE_OFB, iv)
    
    # Calculate hmac
    calc_hmac = HMAC.new(self.shared_hash, digestmod=SHA256)
    calc_hmac.update(encrypted_data)
    calc_hmac = bytes(str(calc_hmac.hexdigest()), "ascii")
    
    data = None
    
    # Perform Anti-Replay check
    if snh == self.session_nonce_hash:
      # Autenticate with HMAC
      if calc_hmac == hmac:      
        # Decrypt data
        data = cipher.decrypt(encrypted_data)
        data = data.ljust(int(origdata_len))[:int(origdata_len)]

        self.__print_verbose("Receiving packet of length {}".format(encrypt_len))
        self.__print_verbose("Encrypted data: {}".format(repr(encrypted_data)))
        self.__print_verbose("Original data: {}".format(data))    
      else:
        self.__print_verbose("Autentication Failed!")
        self.close()
    else:
      self.__print_verbose("Replay Attack detected!")
      self.close()

    return data

  def close(self):
    self.conn.close()
