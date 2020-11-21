import sys
from Crypto.Cipher import AES

a = "139a35422f1d61de3c91787fe0507afd"
b = "b9145a768b7dc489a096b546f43b231f"
#key = bytes.fromhex(a)

cipher = AES.new(b'139a35422f1d61de3c91787fe0507afd', AES.MODE_ECB)
ct_bytes = cipher.encrypt(b'b9145a768b7dc489a096b546f43b231f')

for i in range(len(ct_bytes)):
    print('{:0>2x}'.format(ct_bytes[i]), end = '')
print("")