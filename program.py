import sys
import fileinput
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA384, SHA512, SHA3_384, SHA3_512
from Crypto.PublicKey import RSA
from Crypto.Signature import pss

def doAES(filename, AES_mode, encryption_mode):
    line_counter = 0
    for line in fileinput.input(filename):
        if line_counter == 0:
            key = bytes.fromhex(line.rstrip())
        elif line_counter == 1:
            data = bytes.fromhex(line.rstrip())
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

def doSHA(filename, length, version):
    for line in fileinput.input(filename):
        if version == 2:
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
        elif version == 3:
            if length == 384:
                # Begin Stopwatch
                h = SHA3_384.new()
                h.update(bytes.fromhex(line))
                # End Stopwatch
            elif length == 512:
                # Begin Stopwatch
                h = SHA3_512.new()
                h.update(bytes.fromhex(line))
                # End Stopwatch
            else:
                print("Nel")
            print(h.hexdigest())
        else: 
            print("SHA: Invalid version")

def doRSA(filename, mode):
    line_counter = 0
    for line in fileinput.input(filename):
        if line_counter == 0:
            data = bytes.fromhex(line.rstrip())
            n = int.from_bytes(data, byteorder='big') #requires python 3.2 or above
        elif line_counter == 1:
            data = bytes.fromhex(line.rstrip())
            e = int.from_bytes(data, byteorder='big')
        elif line_counter == 2:
            data = bytes.fromhex(line.rstrip())
            d = int.from_bytes(data, byteorder='big')
            message = b'un mensaje' #falta leer el mensaje
            if mode == "OAEP":
                #cifrado
                key = RSA.construct((n, e, d))
                cipher = PKCS1_OAEP.new(key)
                ciphertext = cipher.encrypt(message)
                data_output = ciphertext
                #falta descifrado
            elif mode == "PSS":
                #firma
                key = RSA.construct((n, e, d))
                h = SHA384.new(message)
                signature = pss.new(key).sign(h)
                data_output = signature
                #falta verificado
            # Imprime texto cifrado o firma
            for i in range(len(data_output)):
                print('{:0>2X}'.format(data_output[i]), end='')
            print("")
        line_counter = (line_counter + 1) % 3


"""
AES-ECB256 BLOCK 128bits
ENCRYPT
Line 0: key
Line 1: plaintext
Line 2: ciphertext
"""
#doAES("./AES/vectores.txt", "ECB", "ENCRYPT")

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

"""
SHA3_384
HASH
Linea i: message
"""
#doSHA("./SHA3/SHA3_384/SHA3_384.rsp", 384, 3)

"""
SHA3_512
HASH
Linea i: message
"""
doSHA("./SHA3/SHA3_512/SHA3_512.rsp", 512, 3)