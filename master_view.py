import os
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

def decrypt_valuables(f):
  # TODO: For Part 2, you'll need to decrypt the contents of this file
  #   - At the moment this system depends upon the size of the text to
  #     decode to be smaller than the pubKey size. This is a bad implementation.
  key = RSA.importKey(open('privkey.der', 'rb').read())
  cipher = PKCS1_OAEP.new(key)
  message = cipher.decrypt(f)
  
  print(message)


if __name__ == "__main__":
  fn = input("Which file in pastebot.net does the botnet master want to view? ")
  if not os.path.exists(os.path.join("pastebot.net", fn)):
    print("The given file doesn't exist on pastebot.net")
    os.exit(1)
  f = open(os.path.join("pastebot.net", fn), "rb").read()
  decrypt_valuables(f)
