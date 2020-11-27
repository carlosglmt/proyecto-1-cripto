import sys
import fileinput
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA384, SHA512, SHA3_384, SHA3_512
from Crypto.PublicKey import RSA, DSA, ECC
from Crypto.Signature import pss, DSS
from Crypto.Random import get_random_bytes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from Crypto.Util.Padding import pad


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
                data_output = cipher_ECB.encrypt(pad(data, AES.block_size))
                # Aqui ya no medir el tiempo
            elif AES_mode == "CBC":
                # Aqui medir el tiempo
                data_output = cipher_CBC.encrypt(pad(data, AES.block_size))  # random iv
                # Aqui ya no medir el tiempo
        elif encryption_mode == "DECRYPT":
            if AES_mode == "ECB":
                # Aqui medir el tiempo
                data_output = cipher_ECB.decrypt(pad(data, AES.block_size))
                # Aqui ya no medir el tiempo
            elif AES_mode == "CBC":
                # Aqui medir el tiempo
                data_output = cipher_CBC.decrypt(pad(data, AES.block_size))  # random iv
                # Aqui ya no medir el tiempo

                # Imprime texto cifrado
                # for i in range(len(data_output)):
                #    print('{:0>2X}'.format(data_output[i]), end = '')
                # print("")


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


def doRSA(vectors, RSA_mode):
    key = RSA.generate(1024)
    cipher_PKCS1 = PKCS1_OAEP.new(key)
    for vector in vectors:
        data = bytes.fromhex(vector)
        if RSA_mode == "OAEP":
            # Cifrar
            data_in = cipher_PKCS1.encrypt(data)
            # Descifrar
            data_out = cipher_PKCS1.decrypt(data_out)
            # Imprime texto cifrado o firma
            for i in range(len(data_in)):
                print('{:0>2X}'.format(data_in[i]), end='')
            print("")
        elif RSA_mode == "PSS":
            # firma
            # medir tiempo
            h = SHA384.new(data)
            data_out = pss.new(key).sign(h)
            # terminar de medir tiempo

            # verificar
            # medir tiempo
            h = SHA384.new(data)
            verifier = pss.new(key)
            # terminar de medir tiempo
            try:
                verifier.verify(h, data_out)
                print("The signature is authentic.")
            except (ValueError, TypeError):
                print("The signature is not authentic.")
        for i in range(len(data_out)):
            print('{:0>2X}'.format(data_out[i]), end='')
        print("")

def doDSS(vectors, mode):
    if mode == "DSA":
        key = DSA.generate(1024)
    elif mode == "ECDSA":
        key = ECC.generate(curve='P-521')

    for vector in vectors:
        data = bytes.fromhex(vector)
        # firma
        # medir tiempo
        h = SHA512.new(data)
        signature = DSS.new(key, 'fips-186-3').sign(h)
        # terminar de medir tiempo

        # verificar
        # medir tiempo
        h = SHA512.new(data)
        verifier = DSS.new(key, 'fips-186-3')
        try:
            verifier.verify(h, signature)
            print("The message is authentic.")
        except ValueError:
            print("The message is not authentic.")
        # terminar de medir tiempo
        for i in range(len(signature)):
            print('{:0>2X}'.format(signature[i]), end='')
        print("")

def doECDSA_BF(vectors):
    private_key = ec.generate_private_key(ec.SECT571K1())
    for vector in vectors:
        data = bytes.fromhex(vector)
        signature = private_key.sign(data, ec.ECDSA(hashes.SHA256()))
        public_key = private_key.public_key()
        try:
            public_key.verify(signature, data, ec.ECDSA(hashes.SHA256()))
            print("The message is authentic.")
        except InvalidSignature:
            print("The message is not authentic.")
            
        for i in range(len(signature)):
            print('{:0>2X}'.format(signature[i]), end='')
        print("")
        
        
vectors = getVectors("vectores.txt")
hash_vectors = getVectors("vectores_hash.txt")

"""
#AES-ECB256 BLOCK 128bits
doAES(vectors, "ECB", "ENCRYPT")

#AES-ECB256 BLOCK 128bits
doAES(vectors, "ECB", "DECRYPT")

#AES-CBC256
doAES(vectors, "CBC", "ENCRYPT")

#AES-CBC256
doAES(vectors, "CBC", "DECRYPT")

#SHA384
doSHA(hash_vectors, 384, 2)

#SHA512
doSHA(hash_vectors, 512, 2)

#SHA3_384
doSHA(hash_vectors, 384, 3)

#SHA3_512
doSHA(hash_vectors, 512, 3)
"""
# RSA CIFRADO
# doRSA(vectors, "OAEP", 0)

# RSA DESCIFRADO
# doRSA(vectors, "OAEP")

# RSA FIRMA y VERIFICADO
#doRSA(vectors, "PSS")

# DSA FIRMA y VERIFICADO
#doDSS(vectors, "DSA")

# ECDSA
doDSS(vectors, "ECDSA")

# ECDSA Binary Field
doECDSA_BF(vectors)