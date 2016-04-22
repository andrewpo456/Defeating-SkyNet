import struct

from Crypto.Cipher import XOR

from dh import create_dh_key, calculate_dh_secret

class StealthConn(object):
    def __init__(self, conn, client=False, server=False, verbose=False):
        self.conn = conn
        self.encryptCipher = None
        self.decryptCipher = None
        self.client = client
        self.server = server
        # self.verbose = verbose - TODO: This and the below line of code is used for verbose output, must remove
        self.verbose = True
        self.initiate_session()
    
    def __print_verbose(self, str):
        if self.verbose:
          print(str)    
    
    def initiate_session(self):
        # Perform the initial connection handshake for agreeing on a shared secret
        # TODO: Is their initial connection work here?

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

        # Default XOR algorithm can only take a key of length 32 - TODO: Implement AES cipher
        self.encryptCipher = XOR.new(shared_hash[:4]) # cipher = AES.new(their_public_key, MODE, iv)
        self.decryptCipher = XOR.new(shared_hash[:4]) # cipher = AES.new(our_private_key, MODE, iv)

    def send(self, data):
        #TODO: Add Anti-Replay Mechanism and HMAC        

        if self.encryptCipher:
            encrypted_data = self.encryptCipher.encrypt(data)
   
            self.__print_verbose("Original data: {}".format(data))
            self.__print_verbose("Encrypted data: {}".format(repr(encrypted_data)))
            self.__print_verbose("Sending packet of length {}".format(len(encrypted_data)))
        else:
            # If the cipher has not been created, just send the plaintext data (BAD)
            encrypted_data = data

        # Encode the data's length into an unsigned two byte int ('H')
        pkt_len = struct.pack('H', len(encrypted_data))
        self.conn.sendall(pkt_len)
        self.conn.sendall(encrypted_data)
        #TODO: Remember to send HMAC too AND IV

    def recv(self):
        #TODO: Add Anti-Replay Mechanism and HMAC

        # Decode the data's length from an unsigned two byte int ('H')        
        pkt_len_packed = self.conn.recv(struct.calcsize('H'))
        pkt_len = struct.unpack('H', pkt_len_packed)[0]
        
        # Recieve the encrypted data
        encrypted_data = self.conn.recv(pkt_len)

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
