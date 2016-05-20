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

  # Generate the private/public key pair using the RSA module
  key = RSA.generate(4096) 
  pri_key_file = open('privkey.der', 'wb')
  pri_key_file.write(key.exportKey('DER'))
  pri_key_file.close()
  
  pub_key = key.publickey()
  pub_key_file = open('pubKey.der', 'wb')
  pub_key_file.write(pub_key.exportKey('DER'))
  pub_key_file.close()
  
  # Create the hash that will be signed and pre-pended to message
  h = SHA256.new(f)
  signer = PKCS1_v1_5.new(key)
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
