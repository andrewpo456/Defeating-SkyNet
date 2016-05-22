import os
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Signature import PKCS1_v1_5

def sign_file(f):  
  #TODO: 
  # - Determine acceptable key size (performance vs security)
  # - Determine whether or not the DER vs PEM (if we need to encrypt key with passphrase
  #   then it must be PEM.
  # - Determine correct signature module (i.e. PKCS1_v1_5 vs ...?)
  # - Need a nonce for freshness ***
  # - Should we harcode the key or re-generate a new one each time the master runs this py file? **** 

  # Import the master key that only the botnet master has access too
  masterkey = RSA.importKey(open('masterkey.pem', 'rb').read())
  
  # Create the hash that will be signed and pre-pended to message
  h = SHA256.new(f)
  signer = PKCS1_v1_5.new(masterkey)
  signature = signer.sign(h)
  print(len(signature))
  
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
