# We're using Python's builtin random
# NOTE: This is not cryptographically strong
import random
import string

def read_hex(data):
    # Remove any spaces or newlines
    data = data.replace(" ", "").replace("\n", "")
    # Read the value as an integer from base 16 (hex)
    return int(data, 16)

def generate_random_string(alphabet=None, length=8, exact=False):
    if not alphabet:
        alphabet = string.ascii_letters + string.digits
    """
    The line below is called a list comprehension and is the same as:
    letters = []
    for i in range(length):
        # Select a random letter from the alphabet and add it to letters
        letters.append(random.choice(alphabet))
    # Join the letters together with no separator
    return ''.join(letters)
    """
    if not exact:
        length = random.randint(length-4 if length-4 > 0 else 1,length+4)
    return ''.join(random.choice(alphabet) for x in range(length))
    
# ANSI X.923 pads the message with zeroes
# The last byte is the number of zeroes added
# This should be checked on unpadding
def ANSI_X923_pad(m, pad_length):
    # Work out how many bytes need to be added
    required_padding = pad_length - (len(m) % pad_length)
    # Use a bytearray so we can add to the end of m
    b = bytearray(m)
    # Then k-1 zero bytes, where k is the required padding
    b.extend(bytes("\x00" * (required_padding-1), "ascii"))
    # And finally adding the number of padding bytes added
    b.append(required_padding)
    return bytes(b)

def ANSI_X923_unpad(m, pad_length):
    # The last byte should represent the number of padding bytes added
    required_padding = m[-1]
    # Ensure that there are required_padding - 1 zero bytes
    if m.count(bytes([0]), -required_padding, -1) == required_padding - 1:
        return m[:-required_padding]
    else:
        # Raise an exception in the case of an invalid padding
        raise AssertionError("Padding was invalid")
