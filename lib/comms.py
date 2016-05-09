import struct
from Crypto.Hash import SHA256
from Crypto.Hash import HMAC
from Crypto import Random
from Crypto.Random import random
from Crypto.Cipher import AES
from lib.helpers import ANSI_X923_pad, ANSI_X923_unpad
from dh import create_dh_key, calculate_dh_secret

# ~ Global variables ~
# We are using SHA256, thefore each HMAC is 64 bytes long (Hexadecimal string format) 
HMAC_LEN    = 64
 # We declare that the counter is sent as a 7 byte number max counter value is therefore '1000000'
COUNTER_LEN = 7

class StealthConn(object):
  def __init__(self, conn, client=False, server=False, verbose=True):
    self.conn               = conn
    self.client             = client
    self.server             = server
    self.verbose            = verbose
    self.session_counter    = None
    self.DEK                = None  # Stored in byte format
    self.signing_secret     = None  # Stored in byte format
        
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
    
  def initiate_session(self):
    """
    Initiates session between client and server bots.
    """
    # Perform the initial connection handshake for agreeing on a shared secret
    if self.server or self.client:
      
      # Calculate diffie-Hellman key pair and send our public key
      my_public_key, my_private_key = create_dh_key()
      self.__packet_send(bytes(str(my_public_key), "ascii"))

      # Receive their public key
      pubKey, key_len = self.__packet_recv()
      their_public_key = int(pubKey)

      # Obtain a shared secret
      shared_hash = calculate_dh_secret(their_public_key, my_private_key)
      shared_hash = bytes(shared_hash, "ascii")
      
      # Derive the following from the shared secret
      #   (a) Symmetric (16 byte) DEK (Data Encryption Key)
      #   (b) Initial session counter value
      #   (c) Secret used in the signing of messages (HMAC)
      self.DEK             = shared_hash[:16]
      self.session_counter = int(shared_hash[17])
      self.signing_secret  = shared_hash[17:]  

  def send(self, data):
    """
    Encrypt and send data over the network.
    """
    # Create the Cipher with the new IV
    iv     = Random.get_random_bytes(AES.block_size)
    cipher = AES.new(self.DEK, AES.MODE_OFB, iv)
    
    # Create the HMAC = hash( signing_secret + session_counter + plaintext)
    hmac = HMAC.new(self.signing_secret, digestmod=SHA256)
    hmac.update(bytes(str(self.session_counter), "ascii"))
    hmac.update(data)
    
    # Construct the data to encrypt = session_counter +  HMAC + data 
    hmac            = bytes(str(hmac.hexdigest()), "ascii")
    ctr_str         = bytes(str(self.session_counter), "ascii")
    ctr_str         = ANSI_X923_pad(ctr_str, COUNTER_LEN)
    data_to_encrypt = ctr_str + hmac + data 
    
    # Encrypt the message
    data_to_encrypt = ANSI_X923_pad(data_to_encrypt, cipher.block_size)
    encrypted_data  = cipher.encrypt(data_to_encrypt)
    
    self.__print_verbose("Original data: {}".format(data))
    self.__print_verbose("Encrypted Data: {}".format(repr(encrypted_data)))
    
    # Append the iv to create the packet
    packet = iv + encrypted_data
    
    # Send the packet
    self.__print_verbose("Sending packet of length {}".format(len(packet)))
    self.__packet_send(packet)
    
    # Increment the session counter, so that the next message will have a new 'unique' freshness identifier
    self.session_counter += 1
	
  def recv(self):
    """
    Recieve and decrypt data from the network.
    """
    # Recieve the paket
    packet, pkt_len = self.__packet_recv()
    
    # Split the packet into iv and encrypted data
    iv             = packet[:AES.block_size]
    encrypted_data = packet[AES.block_size:]
    
    # Initialize decrypt cipher and decrypt data
    cipher  = AES.new(self.DEK, AES.MODE_OFB, iv)
    message = cipher.decrypt(encrypted_data)
    message = ANSI_X923_unpad(message, cipher.block_size)
        
    # Split the data into counter, HMAC and plaintext
    recv_counter = ANSI_X923_unpad(message[:COUNTER_LEN], COUNTER_LEN)      
    recv_hmac    = message[COUNTER_LEN:(COUNTER_LEN + HMAC_LEN)]                       
    plaintext    = message[(COUNTER_LEN + HMAC_LEN):]
    
    # Calculate our own hmac to verify integrity
    calc_hmac = HMAC.new(self.signing_secret, digestmod=SHA256)
    calc_hmac.update(recv_counter)
    calc_hmac.update(plaintext)
    
    # Convert to byte format for comparing data
    calc_hmac = bytes(str(calc_hmac.hexdigest()), "ascii")
    this_counter = bytes(str(self.session_counter), "ascii")
    
    # Perform Anti-Replay check
    if recv_counter == this_counter:
      # Autenticate with HMAC
      if calc_hmac == recv_hmac:              
        data = plaintext
        self.__print_verbose("Receiving packet of length {}".format(pkt_len))
        self.__print_verbose("Encrypted Data: {}".format(repr(encrypted_data)))
        self.__print_verbose("Original data: {}".format(data))         

        self.session_counter += 1 # Increment session counter, to keep lock-step with the other bot       
      else:
        data = None
        self.__print_verbose("Integrity Check Failed!")
        self.close()
    else:
      data = None
      self.__print_verbose("Replay Attack detected!")
      self.close()

    return data

  def close(self):
    self.conn.close()
