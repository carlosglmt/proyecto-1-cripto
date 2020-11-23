import sys
import fileinput
from Crypto.Cipher import AES
from Crypto.Hash import SHA384, SHA512

def doAES_EBC(filename, decryption_mode=False):
    f = open("vectores.txt", "w")
    line_counter = 0
    for line in fileinput.input(filename):
        if line_counter == 0:
            f.write(line)
            key = bytearray.fromhex(line.rstrip())
        elif line_counter == 1:
            f.write(line)
            data = bytearray.fromhex(line.rstrip())
            if not decryption_mode:
                # Aqui medir el tiempo
                cipher = AES.new(key, AES.MODE_ECB)
                data_output = cipher.encrypt(data)
                # Aqui ya no medir el tiempo
            else:
                # Aqui medir el tiempo
                cipher = AES.new(key, AES.MODE_ECB)
                data_output = cipher.decrypt(data)
                # Aqui ya no medir el tiempo

            # Imprime texto cifrado
            for i in range(len(data_output)):
                print('{:0>2X}'.format(data_output[i]), end = '')
            print("")
        line_counter = (line_counter + 1) % 3
    f.close()

def doAES_CBC(filename, decryption_mode=False):
    line_counter = 0
    for line in fileinput.input(filename):
        if line_counter == 0:
            key = bytearray.fromhex(line.rstrip())
        elif line_counter == 1:
            iv = bytearray.fromhex(line.rstrip())
        elif line_counter == 2:
            data = bytearray.fromhex(line.rstrip())
            if not decryption_mode:
                # Aqui medir el tiempo
                cipher = AES.new(key, AES.MODE_CBC, iv)
                data_output = cipher.encrypt(data)
                # Aqui ya no medir el tiempo
            else:
                # Aqui medir el tiempo
                cipher = AES.new(key, AES.MODE_CBC, iv)
                data_output = cipher.decrypt(data)
                # Aqui ya no medir el tiempo

            # Imprime texto cifrado
            for i in range(len(data_output)):
                print('{:0>2X}'.format(data_output[i]), end = '')
            print("")
        line_counter = (line_counter + 1) % 4

def doSHA(filename, length):
    for line in fileinput.input(filename):
        if length == 384:
            # Begin Stopwatch
            h = SHA384.new()
            h.update(bytes.fromhex(line))
            # End Stopwatch
        elif length == 512:
            # Begin Stopwatch
            h = SHA512.new()
            h.update(bytes.fromhex(line))
            # End Stopwatch
        else:
            print("Nel")
        print(h.hexdigest())

"""
AES-ECB256 BLOCK 128bits
ENCRYPT
Line 0: key
Line 1: plaintext
Line 2: ciphertext
"""
doAES_EBC("./AES-ECB-256/vectores")

"""
AES-ECB256 BLOCK 128bits
DECRYPT
Line 0: key
Line 1: ciphertext
Line 2: plaintext
"""
#doAES_EBC("./AES-ECB-256/vectores", True)

"""
AES-CBC256
ENCRYPT
Line 0: key
Line 1: IV
Line 2: plaintext
Line 3: ciphertext
"""
#doAES_CBC("./AES-CBC-256/vectores.txt")

"""
AES-CBC256
DECRYPT
Line 0: key
Line 1: IV
Line 2: plaintext
Line 3: ciphertext
"""
#doAES_CBC("./AES-CBC-256/vectores.txt", True)

"""
SHA384
HASH
Linea i: message
"""
#doSHA("./SHA2/SHA512/vectores.rsp", 384)

"""
SHA512
HASH
Linea i: message
"""
#doSHA("./SHA2/SHA512/vectores.rsp", 512)