import struct
from Crypto.Hash import SHA256
from Crypto.Random import random
from Crypto.Cipher import XOR
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
    Sends data in a 'packet'
    Send 1: Contains the length of data
    Send 2: Contains the data itself
    """
    # Encode the data's length into an unsigned two byte int ('H')
    pkt_len = struct.pack('H', len(data))
    self.conn.sendall(pkt_len)
    self.conn.sendall(data)

  def __packet_recv(self):
    """ 
    Recieves a packet from the network
    and returns data + length of packet
    """
    pkt_len_packed = self.conn.recv(struct.calcsize('H'))
    pkt_len = struct.unpack('H', pkt_len_packed)[0]
    
    return self.conn.recv(pkt_len), pkt_len

  def __sync_session_nonces(self, shared_hash):
    """
    Used to generate and synchronise nonces between
    client and server. This is to prevent relplay
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
      self.session_nonce_h = str.encode(SHA256.new(bytes(calculated_nonce)).hexdigest())
      
      # Encode the string to bytes for transmission and send
      self.__packet_send(self.session_nonce_h)
      self.__print_verbose("Shared session nonce (client): {0}".format(self.session_nonce_h))
    
  def initiate_session(self):
    """
    Initiates session between client and server bots
    """
    # Perform the initial connection handshake for agreeing on a shared secret
    # TODO: Is there initial connection work here?

    # This can be broken into code run just on the server or just on the client
    if self.server or self.client:
      my_public_key, my_private_key = create_dh_key()

      # Send them our public key
      self.send(bytes(str(my_public_key), "ascii"))

      # Receive their public key - Used in Cipher as encryption key
      their_public_key = int(self.recv())

      # Obtain our shared secret
      shared_hash = calculate_dh_secret(their_public_key, my_private_key)
      print("Shared hash: {}".format(shared_hash))
       
      self.__sync_session_nonces(shared_hash)


    # Default XOR algorithm can only take a key of length 32 - TODO: Implement AES cipher
    self.encryptCipher = XOR.new(shared_hash[:4]) # cipher = AES.new(their_public_key, MODE, iv)
    self.decryptCipher = XOR.new(shared_hash[:4]) # cipher = AES.new(our_private_key, MODE, iv)

  def send(self, data):
    """
    Encrypt and send data over the network.
    """
    #TODO: Add Anti-Replay Mechanism
    if self.encryptCipher:
      encrypted_data = self.encryptCipher.encrypt(data)

      self.__print_verbose("Original data: {}".format(data))
      self.__print_verbose("Encrypted data: {}".format(repr(encrypted_data)))
      self.__print_verbose("Sending packet of length {}".format(len(encrypted_data)))
    else:
      # If the cipher has not been created, just send the plaintext data (BAD)
      encrypted_data = data

    #TODO: Remember to send HMAC too AND IV
    self.__packet_send(encrypted_data)

  def recv(self):
    """
    Recieve and decrypt data from the network.
    """
    #TODO: Add Anti-Replay Mechanism and HMAC
    # Recieve the encrypted data        
    encrypted_data, pkt_len = self.__packet_recv()

    if self.decryptCipher:
      data = self.decryptCipher.decrypt(encrypted_data)

      self.__print_verbose("Receiving packet of length {}".format(pkt_len))
      self.__print_verbose("Encrypted data: {}".format(repr(encrypted_data)))
      self.__print_verbose("Original data: {}".format(data))    
    else:
      data = encrypted_data

    return data

  def close(self):
    self.conn.close()
