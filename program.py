import sys
import fileinput
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA384, SHA512, SHA3_384, SHA3_512
from Crypto.PublicKey import RSA
from Crypto.Signature import pss
from Crypto.Random import get_random_bytes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

def getVectors(filename):
    vectors = []
    for vector in fileinput.input(filename):
        vectors.append(vector.rstrip())
    return vectors

def doAES(vectors, AES_mode, encryption_mode):
    key = get_random_bytes(32)
    cipher_ECB = AES.new(key, AES.MODE_ECB)
    cipher_CBC = AES.new(key, AES.MODE_CBC) 
    for vector in vectors:
        data = bytes.fromhex(vector)
        if encryption_mode == "ENCRYPT":
            if AES_mode == "ECB":
                # Aqui medir el tiempo
                data_output = cipher_ECB.encrypt(data)
                # Aqui ya no medir el tiempo
            elif AES_mode == "CBC":
                # Aqui medir el tiempo
                data_output = cipher_CBC.encrypt(data) #random iv
                # Aqui ya no medir el tiempo
        elif encryption_mode == "DECRYPT":
            if AES_mode == "ECB":
                # Aqui medir el tiempo
                data_output = cipher_ECB.decrypt(data)
                # Aqui ya no medir el tiempo
            elif AES_mode == "CBC":
                # Aqui medir el tiempo
                data_output = cipher_CBC.decrypt(data) #random iv
                # Aqui ya no medir el tiempo
                
            # Imprime texto cifrado
            #for i in range(len(data_output)):
            #    print('{:0>2X}'.format(data_output[i]), end = '')
            #print("")

def doSHA(vectors, length, version):
    for vector in vectors:
        data = bytes.fromhex(vector)
        if version == 2:
            if length == 384:
                # Begin Stopwatch
                h = SHA384.new()
                h.update(data)
                # End Stopwatch
            elif length == 512:
                # Begin Stopwatch
                h = SHA512.new()
                h.update(data)
                # End Stopwatch
            print(h.hexdigest())
        elif version == 3:
            if length == 384:
                # Begin Stopwatch
                h = SHA3_384.new()
                h.update(data)
                # End Stopwatch
            elif length == 512:
                # Begin Stopwatch
                h = SHA3_512.new()
                h.update(data)
                # End Stopwatch
            print(h.hexdigest())


def doRSA(vectors, RSA_mode, op_mode):
    key = RSA.generate(1024)    
    cipher_PKCS1 = PKCS1_OAEP.new(key)
    for vector in vectors:
        data = bytes.fromhex(vector)
        if RSA_mode == "OAEP":
            #cifrado
            if op_mode == 0:    #Cifrar
                ciphertext = cipher_PKCS1.encrypt(data)
            else:               #Descifrar
                ciphertext = cipher_PKCS1.decrypt(data)
        elif RSA_mode == "PSS":
            
            #firma
            #medir tiempo
            h = SHA384.new(data)
            signature = pss.new(key).sign(h)
            #terminar de medir tiempo
    
            #verificar
            #medir tiempo
            h = SHA384.new(data)
            verifier = pss.new(key)
            verifier.verify(h, signature)
            #terminar de medir tiempo
            
        # Imprime texto cifrado o firma
        #for i in range(len(data_output)):
        #    print('{:0>2X}'.format(data_output[i]), end='')
        #print("")

vectors = getVectors("vectores.txt")
hash_vectors = getVectors("vectores_hash.txt")

"""
AES-ECB256 BLOCK 128bits
ENCRYPT
Line 0: key
Line 1: plaintext
Line 2: ciphertext
"""
doAES(vectors, "ECB", "ENCRYPT")

"""
AES-ECB256 BLOCK 128bits
DECRYPT
Line 0: key
Line 1: ciphertext
Line 2: plaintext
"""
doAES(vectors, "ECB", "DECRYPT")

"""
AES-CBC256
ENCRYPT
Line 0: key
Line 1: IV
Line 2: plaintext
Line 3: ciphertext
"""
doAES(vectors, "CBC", "ENCRYPT")

"""
AES-CBC256
DECRYPT
Line 0: key
Line 1: IV
Line 2: plaintext
Line 3: ciphertext
"""
doAES(vectors, "CBC", "DECRYPT")

"""
SHA384
HASH
Linea i: message
"""
doSHA(hash_vectors, 384, 2)

"""
SHA512
HASH
Linea i: message
"""
doSHA(hash_vectors, 512, 2)

"""
SHA3_384
HASH
Linea i: message
"""
doSHA(hash_vectors, 384, 3)

"""
SHA3_512
HASH
Linea i: message
"""
doSHA(hash_vectors, 512, 3)