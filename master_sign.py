import os
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Signature import PKCS1_v1_5

def sign_file(f):  
  # Import the master (private) RSA key to sign file
  masterkey = RSA.importKey(open('masterkey.pem', 'rb').read())
  
  # Create the signature of the hash that will be pre-pended to the message
  h = SHA256.new(f)
  signer = PKCS1_v1_5.new(masterkey)
  signature = signer.sign(h)

  return signature + f


if __name__ == "__main__":
  fn = input("Which file in pastebot.net should be signed? ")
  if not os.path.exists(os.path.join("pastebot.net", fn)):
    print("The given file doesn't exist on pastebot.net")
    os.exit(1)
  f = open(os.path.join("pastebot.net", fn), "rb").read()
  signed_f = sign_file(f)
  signed_fn = os.path.join("pastebot.net", fn + ".signed")
  out = open(signed_fn, "wb")
  out.write(signed_f)
  out.close()
  print("Signed file written to", signed_fn)
