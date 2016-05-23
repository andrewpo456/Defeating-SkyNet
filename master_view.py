import os
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher import AES
from lib.helpers import ANSI_X923_pad, ANSI_X923_unpad

def decrypt_valuables(f):
  # Import the rsa private key and create the rsa decrypt cipher
  masterkey = RSA.importKey(open('masterkey.pem', 'rb').read())
  rsa_cipher = PKCS1_OAEP.new(masterkey)
  
  # Calculate the length of the encrypted cipher info (in bytes)
  info_len = int((masterkey.size() + 1)/8)
  
  # Seperate the encrypted cipher info and message
  encrypt_cipher_info = f[:info_len]
  encrypted_message   = f[info_len:]
  
  # Decrypt iv and the symmetric key
  info    = rsa_cipher.decrypt(encrypt_cipher_info)
  iv      = info[:AES.block_size]
  symmkey = info[AES.block_size:(AES.block_size*2)]
  
  # Decrypt the message using the found iv and symmetric key
  cipher  = AES.new(symmkey, AES.MODE_OFB, iv)
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
