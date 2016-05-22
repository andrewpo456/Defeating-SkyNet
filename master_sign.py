import os
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Signature import PKCS1_v1_5

def sign_file(f):  
  #TODO: 
  # - Need a nonce for freshness ***
  
  # Import the master key that only the botnet master has access to
  masterkey = RSA.importKey(open('masterkey.pem', 'rb').read())
  
  # Create the hash that will be signed and pre-pended to message
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
