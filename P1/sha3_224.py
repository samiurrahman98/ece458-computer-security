import hashlib
import binascii

"""
sha3_224_hex is design to take a hexadecimal string as the input. 
You should call sha3_224() in your project for both DSA signature and sha3_224
Don't directly call hashlib.sha3_224() which only takes a character string (then encode the string to utf-8 format) as the input.
No prefix for the input string and len(hexstr) is even
e.g.  sha3_224_hex("4c")
"""

def sha3_224_hex(hexstr):
	if len(hexstr)%2!=0:
		raise ValueError("Error: Length of hex string should be even")
	m=hashlib.sha3_224()
	data=binascii.a2b_hex(str(hexstr))
	m.update(data)
	return m.hexdigest()

print(sha3_224_hex("38363138363536383336"))