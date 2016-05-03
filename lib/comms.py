import struct
from Crypto.Hash import SHA256
from Crypto.Hash import HMAC
from Crypto import Random
from Crypto.Random import random
from Crypto.Cipher import AES
from lib.helpers import ANSI_X923_pad, ANSI_X923_unpad
from dh import create_dh_key, calculate_dh_secret

class StealthConn(object):
  def __init__(self, conn, client=False, server=False, verbose=True):
    self.conn               = conn
    self.client             = client
    self.server             = server
    self.verbose            = verbose
    self.session_counter    = 0    
    # Note that all variables below are stored in byte format
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


    
  def initiate_session(self):
    """
    Initiates session between client and server bots.
    """
    # Perform the initial connection handshake for agreeing on a shared secret
    if self.server or self.client:
      # Calculate diffie-Hellman key pair and send our public key
      my_public_key, self.my_private_key = create_dh_key()
      self.__packet_send(bytes(str(my_public_key), "ascii"))

      # Receive their public key - Used in Cipher as encryption key
      pubKey, key_len = self.__packet_recv()
      self.their_public_key = int(pubKey)

      # Obtain the shared secret
      self.shared_hash = calculate_dh_secret(self.their_public_key, self.my_private_key)
      self.shared_hash = bytes(self.shared_hash, "ascii")        	
      
      # Convert the keys to byte format and truncate to a size of 32 (16 ,24 and 32 bit keys
      # allowed only in AES encryption cipher)
      self.their_public_key = bytes(str(self.their_public_key), "ascii").ljust(32)[:32]
      self.my_private_key   = bytes(str(self.my_private_key), "ascii").ljust(32)[:32]
	
  def send(self, data):
    """
    Encrypt and send data over the network.
    """
    self.__print_verbose("Original data: {}".format(data))
    
    # Initialise the encrypt Cipher (a new IV will be generated for each encyrption)
    iv = Random.get_random_bytes(AES.block_size)
    cipher = AES.new(self.their_public_key, AES.MODE_OFB, iv)
    
    # Create the HMAC = hash( shared_secret + session_counter + plaintext)
    # and convert to bytes
    hmac = HMAC.new(self.shared_hash, digestmod=SHA256)
    hmac.update(bytes(str(self.session_counter), "ascii"))
    hmac.update(data)
    hmac = bytes(str(hmac), "ascii")
    
    # Construct the message = session_counter + data + HMAC 
    ctr_str = bytes(str(self.session_counter), "ascii")
    ctr_str = ANSI_X923_pad(ctr_str, 7) # The data is padded to 7 bytes as this is what reciever expects
    message = ctr_str + data + hmac
    
    # Encrypt the message
    message = ANSI_X923_pad(message, cipher.block_size) # TODO: Determine if need to pad in OFB is bug or not
    encrypted_data = cipher.encrypt(message)
    self.__print_verbose("Sending packet of length {}".format(len(encrypted_data)))
    self.__print_verbose("Encrypted data: {}".format(repr(encrypted_data)))
    
    # Append the iv
    message_to_send = iv + encrypted_data
    
    # Send the encrypted data with relevant information
    self.__packet_send(message_to_send) # Send the encrypted data
    
    # Increment the session counter, so that the next message will have a new 'unique' identifier
    self.session_counter += 1
	
  def recv(self):
    """
    Recieve and decrypt data from the network.
    """
    # Recieve the message
    message, encrypt_len = self.__packet_recv() # The encrypted data
    
    iv = message[:16]
    encrypted_data = message[16:]
    
    # Initialize decrypt cipher
    cipher = AES.new(self.my_private_key, AES.MODE_OFB, iv)
    
    # Calculate hmac
    calc_hmac = HMAC.new(self.shared_hash, digestmod=SHA256)
    calc_hmac.update(encrypted_data)
    calc_hmac = bytes(str(calc_hmac.hexdigest()), "ascii")
    
    # Convert session counter to byte format
    this_counter = bytes(str(self.session_counter), "ascii")
    data = None
    
    # Perform Anti-Replay check
    if counter == this_counter:
      # Autenticate with HMAC
      if calc_hmac == hmac:      
        # Decrypt data
        data = cipher.decrypt(encrypted_data)
        data = ANSI_X923_unpad(data, cipher.block_size)
        
        # Increment session counter, to keep lock-step
        # with the other bot
        self.session_counter += 1

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
