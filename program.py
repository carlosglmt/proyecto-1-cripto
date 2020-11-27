import fileinput
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA384, SHA512, SHA3_384, SHA3_512
from Crypto.PublicKey import RSA, DSA, ECC
from Crypto.Signature import pss, DSS
from Crypto.Random import get_random_bytes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from Crypto.Util.Padding import pad
from timeit import default_timer as timer

"""
This functions receives one file consisting of one vector per line
The vector size varies from 1 to 86 bytes
"""
def getVectors(filename): 
    vectors = []
    for vector in fileinput.input(filename):#test vectors are read from file
        vectors.append(vector.rstrip()) #strip end line character from string and save vector in list
    return vectors

"""
This function receives three parameters:
1: vectors list 
2: AES_mode which can be "ENCRYPT" or "DECRYPT"
3: encryption_mode which can be "ECB" or "CBC"
"""
def doAES(vectors, AES_mode, encryption_mode):
    key = get_random_bytes(32) #a random key is created (256 bits)
    cipher_ECB = AES.new(key, AES.MODE_ECB) #an AES ECB cipher object is created with the key
    cipher_CBC = AES.new(key, AES.MODE_CBC) #an AES CBC cipher object is created with the key
    for vector in vectors:
        data = bytes.fromhex(vector) #vector is converted from hex to a binary object
        if encryption_mode == "ENCRYPT":
            if AES_mode == "ECB":
                start = timer() #begin time measure
                data_output = cipher_ECB.encrypt(pad(data, AES.block_size)) #pad message and encrypt
                end = timer() #end time measure
                print(start-end) #total execution time
            elif AES_mode == "CBC":
                start = timer() #begin time measure
                data_output = cipher_CBC.encrypt(pad(data, AES.block_size))  # random iv
                end = timer() #end time measure
                print(start-end) #total execution time
        elif encryption_mode == "DECRYPT":
            if AES_mode == "ECB":
                start = timer() #begin time measure
                data_output = cipher_ECB.decrypt(pad(data, AES.block_size)) #pad message and decrypt
                end = timer() #end time measure
                print(start-end) #total execution time
            elif AES_mode == "CBC":
                start = timer() #begin time measure
                data_output = cipher_CBC.decrypt(pad(data, AES.block_size))  # random iv
                end = timer() #end time measure
                print(start-end) #total execution time
                
        # Imprime texto cifrado
        # for i in range(len(data_output)):
        #    print('{:0>2X}'.format(data_output[i]), end = '')
        # print("")

"""
This function receives three parameters:
1: vectors list 
2: length in bits of the message digest. It can be 384 or 512.
3: version of the algorithm. Use 2 for SHA-2 or 3 for SHA-3.
"""
def doSHA(vectors, length, version):
    for vector in vectors:
        data = bytes.fromhex(vector) #vector is converted from hex to a binary object
        if version == 2:
            if length == 384:
                start = timer() #begin time measure
                h = SHA384.new()
                h.update(data) #message is hashed
                end = timer() #end time measure
                print(start-end) #total execution time
            elif length == 512:
                start = timer() #begin time measure
                h = SHA512.new()
                h.update(data) #message is hashed
                end = timer() #end time measure
                print(start-end) #total execution time
            print(h.hexdigest())
        elif version == 3:
            if length == 384:
                start = timer() #begin time measure
                h = SHA3_384.new()
                h.update(data) #message is hashed
                end = timer() #end time measure
                print(start-end) #total execution time
            elif length == 512:
                start = timer() #begin time measure
                h = SHA3_512.new()
                h.update(data) #message is hashed
                end = timer() #end time measure
                print(start-end) #total execution time
            #print(h.hexdigest())

"""
This function receives two parameters:
1: vectors list 
2: RSA_mode string. Use "OAEP" to encrypt/decrypt or "PSS" to sign/verify
"""
def doRSA(vectors, RSA_mode):
    key = RSA.generate(1024) #a random key is created (1024 bits)
    cipher_PKCS1 = PKCS1_OAEP.new(key) #a RSA-OAEP cipher object is created
    for vector in vectors:
        data = bytes.fromhex(vector) #vector is converted from hex to a binary object
        if RSA_mode == "OAEP":
            # Encrypt
            start = timer() #begin time measure
            data_in = cipher_PKCS1.encrypt(data) #message encryption
            end = timer() #end time measure
            print(start-end) #total execution time
            # Decrypt
            start = timer() #begin time measure
            data_out = cipher_PKCS1.decrypt(data_in) #message decryption
            end = timer() #end time measure
            print(start-end) #total execution time
            # Print result
            #for i in range(len(data_in)):
            #    print('{:0>2X}'.format(data_in[i]), end='')
            #print("")
        elif RSA_mode == "PSS":
            # Signature
            start = timer() #begin time measure
            h = SHA384.new(data)
            data_out = pss.new(key).sign(h) #hash is signed with private key
            end = timer() #end time measure
            print(start-end) #total execution time
           
            # Verification
            start = timer() #begin time measure
            h = SHA384.new(data)
            verifier = pss.new(key) #verifier uses the public key
            try:
                verifier.verify(h, data_out) #data is verified
                end = timer() #end time measure
                print(start-end) #total execution time
                #print("The signature is authentic.")
            except (ValueError, TypeError):
                pass
                #print("The signature is not authentic.")
           
        #for i in range(len(data_out)):
        #    print('{:0>2X}'.format(data_out[i]), end='')
        #print("")
"""
This function is used for two different digital signature algorithms:
DSA and ECDSA with prime field
It receives two parameters:
1: vectors list 
2: mode which can be "DSA" or "ECDSA"
"""
def doDSS(vectors, mode):
    if mode == "DSA":
        key = DSA.generate(1024)
    elif mode == "ECDSA":
        key = ECC.generate(curve='P-521')
    for vector in vectors:
        data = bytes.fromhex(vector) #vector is converted from hex to a binary object
        start = timer() #begin time measure
        h = SHA512.new(data)
        signature = DSS.new(key, 'fips-186-3').sign(h) #data is signed with private key
        end = timer() #end time measure
        print(start-end) #total execution time

        start = timer() #begin time measure
        h = SHA512.new(data)
        verifier = DSS.new(key, 'fips-186-3') #verifier uses the public key
        try:
            verifier.verify(h, signature) #data is verified
            end = timer() #end time measure
            print(start-end) #total execution time
            #print("The message is authentic.")
        except ValueError:
            pass
            #print("The message is not authentic.")
        #for i in range(len(signature)):
        #    print('{:0>2X}'.format(signature[i]), end='')
        #print("")

"""
This function is used to digitally sign a message using ECDSA with binary field and Koblitz Field
It receives one parameter
1: vectors list 
"""
def doECDSA_BF(vectors):
    private_key = ec.generate_private_key(ec.SECT571K1())
    for vector in vectors:
        data = bytes.fromhex(vector) #vector is converted from hex to a binary object
        start = timer() #begin time measure
        signature = private_key.sign(data, ec.ECDSA(hashes.SHA256())) #data is signed with private key
        end = timer() #end time measure
        print(start-end) #total execution time
        start = timer() #begin time measure
        public_key = private_key.public_key()
        try:
            public_key.verify(signature, data, ec.ECDSA(hashes.SHA256())) #data is verified with public key
            end = timer() #end time measure
            print(start-end) #total execution time
            #print("The message is authentic.")
        except InvalidSignature:
            pass
            #print("The message is not authentic.")
            
        #for i in range(len(signature)):
        #   print('{:0>2X}'.format(signature[i]), end='')
        #print("")
        
# Read vectors for AES, RSA, DSA and ECDSA  
vectors = getVectors("vectors.txt")
# Read vectors for SHA2 and SHA3
hash_vectors = getVectors("hash_vectors.txt")



#AES-ECB256
doAES(vectors, "ECB", "ENCRYPT")

#AES-ECB256
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

#RSA CIFRADO Y DESCIFRADO
doRSA(vectors, "OAEP")

#RSA FIRMA y VERIFICADO
doRSA(vectors, "PSS")

#DSA FIRMA y VERIFICADO
doDSS(vectors, "DSA")

#ECDSA Prime Field
doDSS(vectors, "ECDSA")

# ECDSA Binary Field
doECDSA_BF(vectors)
