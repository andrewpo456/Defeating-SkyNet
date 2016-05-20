import os
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher import AES
from lib.helpers import ANSI_X923_pad, ANSI_X923_unpad

def decrypt_valuables(f):
  # Import the rsa private key and create the rsa decrypt cipher
  rsa_key = RSA.importKey(open('privkey.der', 'rb').read())
  rsa_cipher = PKCS1_OAEP.new(rsa_key)
  
  # Calculate the length of the encrypted symmetric key (in bytes)
  encrypt_k_len = int((rsa_key.size() + 1)/8)
  
  #Obtain iv, the encrypted symmetric key and the encrypted message
  iv = f[:AES.block_size]
  encrypted_key = f[AES.block_size:(AES.block_size + encrypt_k_len)]
  encrypted_message = f[(AES.block_size + encrypt_k_len):]
  
  # Unencrypt the symmetric key
  key = rsa_cipher.decrypt(encrypted_key)

  # Decrypt the message using the found iv and symmetric key
  cipher  = AES.new(key, AES.MODE_OFB, iv)
  message = cipher.decrypt(encrypted_message)
  message = ANSI_X923_unpad(message, cipher.block_size)
  
  print(message)


if __name__ == "__main__":
  fn = input("Which file in pastebot.net does the botnet master want to view? ")
  if not os.path.exists(os.path.join("pastebot.net", fn)):
    print("The given file doesn't exist on pastebot.net")
    os.exit(1)
  f = open(os.path.join("pastebot.net", fn), "rb").read()
  decrypt_valuables(f)
