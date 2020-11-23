import sys
import fileinput
from Crypto.Cipher import AES
from Crypto.Hash import SHA384, SHA512

def doAES(filename, AES_mode, encryption_mode):
    line_counter = 0
    for line in fileinput.input(filename):
        if line_counter == 0:
            key = bytearray.fromhex(line.rstrip())
        elif line_counter == 1:
            data = bytearray.fromhex(line.rstrip())
            if encryption_mode == "ENCRYPT":
                if AES_mode == "ECB":
                    # Aqui medir el tiempo
                    cipher = AES.new(key, AES.MODE_ECB)
                    data_output = cipher.encrypt(data)
                    # Aqui ya no medir el tiempo
                elif AES_mode == "CBC":
                    # Aqui medir el tiempo
                    cipher = AES.new(key, AES.MODE_CBC) #random iv
                    data_output = cipher.encrypt(data)
                    # Aqui ya no medir el tiempo
            elif encryption_mode == "DECRYPT":
                if AES_mode == "ECB":
                    # Aqui medir el tiempo
                    cipher = AES.new(key, AES.MODE_ECB)
                    data_output = cipher.decrypt(data)
                    # Aqui ya no medir el tiempo
                elif AES_mode == "CBC":
                    # Aqui medir el tiempo
                    cipher = AES.new(key, AES.MODE_CBC)  # random iv
                    data_output = cipher.decrypt(data)
                    # Aqui ya no medir el tiempo

            # Imprime texto cifrado
            for i in range(len(data_output)):
                print('{:0>2X}'.format(data_output[i]), end = '')
            print("")
        line_counter = (line_counter + 1) % 2

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
doAES("./AES/vectores.txt", "ECB", "ENCRYPT")

"""
AES-ECB256 BLOCK 128bits
DECRYPT
Line 0: key
Line 1: ciphertext
Line 2: plaintext
"""
#doAES("./AES/vectores.txt", "ECB", "DECRYPT")

"""
AES-CBC256
ENCRYPT
Line 0: key
Line 1: IV
Line 2: plaintext
Line 3: ciphertext
"""
#doAES("./AES/vectores.txt", "CBC", "ENCRYPT")

"""
AES-CBC256
DECRYPT
Line 0: key
Line 1: IV
Line 2: plaintext
Line 3: ciphertext
"""
#doAES("./AES/vectores.txt", "CBC", "DECRYPT")

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