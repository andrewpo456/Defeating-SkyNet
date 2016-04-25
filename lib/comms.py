import struct
from Crypto.Hash import SHA256
from Crypto.Hash import HMAC
from Crypto.Random import random
from Crypto.Cipher import XOR
from Crypto.Cipher import AES
from dh import create_dh_key, calculate_dh_secret

class StealthConn(object):
  def __init__(self, conn, client=False, server=False, verbose=True):
    self.conn = conn
    self.encryptCipher = None
    self.decryptCipher = None
    self.session_nonce_hash = None # Note this is stored in byte format
    self.client = client
    self.server = server
    self.verbose = verbose
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
      
      # Recieve the session_nonce_hash from the client and decode
      self.session_nonce_hash, pkt_len = self.__packet_recv()
      self.__print_verbose("Shared session nonce (server): {0}".format(self.session_nonce_hash))
      
      
    if self.client:
      # Generate the pseudorandom client nonce and recieve the server nonce
      cnonce = bytes(str(random.randint(1, 2**4096)), "ascii") # The client nonce is kept secret and thrown away afterwards
      snonce, pkt_len = self.__packet_recv()

      # Calculate the session nonces with shared secret hash
      calculated_nonce = snonce + cnonce + str.encode(shared_hash)
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
      my_public_key, my_private_key = create_dh_key()

      # Send them our public key
      self.__packet_send(bytes(str(my_public_key), "ascii"))

      # Receive their public key - Used in Cipher as encryption key
      pubKey, key_len = self.__packet_recv()
      their_public_key = int(pubKey)

      # Obtain our shared secret
      shared_hash = calculate_dh_secret(their_public_key, my_private_key)
      print("Shared hash: {}".format(shared_hash))
       
      self.__sync_session_nonces(shared_hash)

	#get IV value for creating ciphers
	iv = Crypto.Random.OSRNG.posix.new().read(AES.block_size)
	
	#iv = int(hexlify(Random.new().read(AES.block_size)), 16)
	#iv_encrypt_counter = Counter.new(128, initial_value=ctr_iv)
	#iv_decrypt_counter = Counter.new(128, initial_value=ctr_iv)
	#self.encryptCipher = AES.new(their_public_key, AES.MODE_OFB, iv_encrypt_counter)
	#self.decryptCipher = AES.new(my_private_key, AES.MODE_OFB, iv_decrypt_counter)
      	
    # Default XOR algorithm can only take a key of length 32  
	## XOR.new(shared_hash[:4]) # cipher = AES.new(their_public_key, AES.MODE_OFB, iv)
    ##XOR.new(shared_hash[:4]) # cipher = AES.new(our_private_key, AES.MODE_OFB, iv)
	
	#Implement AES cipher
	self.encryptCipher = AES.new(their_public_key, AES.MODE_OFB, iv)
    self.decryptCipher = AES.new(my_private_key, AES.MODE_OFB, iv) 

  def send(self, data):
    """
    Encrypt and send data over the network.
    """
    if self.encryptCipher:
      encrypted_data = self.encryptCipher.encrypt(data)

      self.__print_verbose("Original data: {}".format(data))
      self.__print_verbose("Encrypted data: {}".format(repr(encrypted_data)))
      self.__print_verbose("Sending packet of length {}".format(len(encrypted_data)))
    else:
      # If the cipher has not been created, just send the plaintext data (BAD)
      encrypted_data = data

    #TODO: Remember to send HMAC too AND IV
	mac = "bb46120970e71e1d63253a124c19ed4bd7f4268410f4e57e637d66f82d30ac3e"
    self.__packet_send(self.session_nonce_hash)  # Send the session nonce (for Anti-Replay attacks)
    self.__packet_send(encrypted_data)           # Send the encrypted data
    self.__packet_send(bytes(mac, "ascii"))   # TODO: Replace with HMAC
	self.__packet_send(bytes(shared_hash, "ascii"))  
	
  def recv(self):
    """
    Recieve and decrypt data from the network.
    """
    # Recieve the encrypted data with session nonce and HMAC
    snh, snh_len = self.__packet_recv()        
    encrypted_data, data_len = self.__packet_recv()
    hmac, hmac_len = self.__packet_recv()
	secret, secret_len = self.__packet_recv()
    
    data = None # Set data to none initially
    
    # Perform Anti-Replay check
    if snh == self.session_nonce_hash:
      # Autenticate with HMAC
      calc_hmac = HMAC.new(secret, digestmod=SHA256) # TODO Implement calculation - hash(shared_hash + encrypted_data)
      calc_hmac.update(encrypted_data)
	  
      if bytes(str(calc_hmac), 'ascii') == hmac:      
        # Decrypt data
        if self.decryptCipher:
          data = self.decryptCipher.decrypt(encrypted_data)

          self.__print_verbose("Receiving packet of length {}".format(data_len))
          self.__print_verbose("Encrypted data: {}".format(repr(encrypted_data)))
          self.__print_verbose("Original data: {}".format(data))    
        else:
          data = encrypted_data
      else:
        self.__print_verbose("Autentication Failed!")
        self.close()
    else:
      self.__print_verbose("Replay Attack detected!")
      self.close()

    return data

  def close(self):
    self.conn.close()
