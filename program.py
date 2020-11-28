"""
 Created by: 
    López Martínez Andrés
    Morales Téllez Carlos Gamaliel
    Pérez Quiroz Miguel Ángel
"""
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
    counter = 0
    addition = 0
    key = get_random_bytes(32) #a random key is created (256 bits)
    cipher_ECB = AES.new(key, AES.MODE_ECB) #an AES ECB cipher object is created with the key
    cipher_CBC = AES.new(key, AES.MODE_CBC) #an AES CBC cipher object is created with the key
    for vector in vectors:
        counter += 1
        data = bytes.fromhex(vector) #vector is converted from hex to a binary object
        if encryption_mode == "ENCRYPT":
            if AES_mode == "ECB":
                start = timer() #begin time measure
                data_output = cipher_ECB.encrypt(pad(data, AES.block_size)) #pad message and encrypt
                end = timer() #end time measure
                #print(end-start) #total execution time
                addition += end - start
            elif AES_mode == "CBC":
                start = timer() #begin time measure
                data_output = cipher_CBC.encrypt(pad(data, AES.block_size))  # random iv
                end = timer() #end time measure
                #print(end-start) #total execution time
                addition += end - start
        elif encryption_mode == "DECRYPT":
            if AES_mode == "ECB":
                start = timer() #begin time measure
                data_output = cipher_ECB.decrypt(pad(data, AES.block_size)) #pad message and decrypt
                end = timer() #end time measure
                #print(end-start) #total execution time
                addition += end - start
            elif AES_mode == "CBC":
                start = timer() #begin time measure
                data_output = cipher_CBC.decrypt(pad(data, AES.block_size))  # random iv
                end = timer() #end time measure
                #print(end-start) #total execution time
                addition += end - start
        
        # Imprime texto cifrado
        # for i in range(len(data_output)):
        #    print('{:0>2X}'.format(data_output[i]), end = '')
        # print("")
    return addition / counter

"""
This function receives three parameters:
1: vectors list 
2: length in bits of the message digest. It can be 384 or 512.
3: version of the algorithm. Use 2 for SHA-2 or 3 for SHA-3.
"""
def doSHA(vectors, length, version):
    counter = 0
    addition = 0
    for vector in vectors:
        counter += 1
        data = bytes.fromhex(vector) #vector is converted from hex to a binary object
        if version == 2:
            if length == 384:
                start = timer() #begin time measure
                h = SHA384.new()
                h.update(data) #message is hashed
                end = timer() #end time measure
                #print(end-start) #total execution time
                addition += end - start
            elif length == 512:
                start = timer() #begin time measure
                h = SHA512.new()
                h.update(data) #message is hashed
                end = timer() #end time measure
                #print(end-start) #total execution time
                addition += end - start
            #print(h.hexdigest())
        elif version == 3:
            if length == 384:
                start = timer() #begin time measure
                h = SHA3_384.new()
                h.update(data) #message is hashed
                end = timer() #end time measure
                #print(end-start) #total execution time
                addition += end - start
            elif length == 512:
                start = timer() #begin time measure
                h = SHA3_512.new()
                h.update(data) #message is hashed
                end = timer() #end time measure
                #print(end-start) #total execution time
                addition += end - start
            #print(h.hexdigest())
    return addition / counter

"""
This function receives two parameters:
1: vectors list 
2: RSA_mode string. Use "OAEP" to encrypt/decrypt or "PSS" to sign/verify
"""
def doRSA(vectors, RSA_mode):
    counter = 0 #This variable stores the numbers of vectors read
    addition1 = 0  #This variable stores execution times for encrypt/sign
    addition2 = 0  #This variable stores execution times for decrypt/verify
    key = RSA.generate(1024) #a random key is created (1024 bits)
    cipher_PKCS1 = PKCS1_OAEP.new(key) #a RSA-OAEP cipher object is created
    for vector in vectors:
        counter += 1
        data = bytes.fromhex(vector) #vector is converted from hex to a binary object
        if RSA_mode == "OAEP":
            # Encrypt
            start = timer() #begin time measure
            data_in = cipher_PKCS1.encrypt(data) #message encryption
            end = timer() #end time measure
            #print(end-start) #total execution time
            addition1 += end - start
            # Decrypt
            start = timer() #begin time measure
            data_out = cipher_PKCS1.decrypt(data_in) #message decryption
            end = timer() #end time measure
            #print(end-start) #total execution time
            addition2 += end - start
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
            #print(end-start) #total execution time
            addition1 += end - start
           
            # Verification
            start = timer() #begin time measure
            h = SHA384.new(data)
            verifier = pss.new(key) #verifier uses the public key
            try:
                verifier.verify(h, data_out) #data is verified
                end = timer() #end time measure
                #print(end-start) #total execution time
                addition2 += end - start
                #print("The signature is authentic.")
            except (ValueError, TypeError):
                pass
                #print("The signature is not authentic.")
           
        #for i in range(len(data_out)):
        #    print('{:0>2X}'.format(data_out[i]), end='')
        #print("")
    return addition1 / counter, addition2 / counter

"""
This function is used for two different digital signature algorithms:
DSA and ECDSA with prime field
It receives two parameters:
1: vectors list 
2: mode which can be "DSA" or "ECDSA"
"""
def doDSS(vectors, mode):
    counter = 0
    addition_sign = 0
    addition_verify = 0
    if mode == "DSA":
        key = DSA.generate(1024)
    elif mode == "ECDSA":
        key = ECC.generate(curve='P-521')
    for vector in vectors:
        counter += 1
        data = bytes.fromhex(vector) #vector is converted from hex to a binary object
        start = timer() #begin time measure
        h = SHA512.new(data)
        signature = DSS.new(key, 'fips-186-3').sign(h) #data is signed with private key
        end = timer() #end time measure
        #print(end-start) #total execution time
        addition_sign += end - start
    
        start = timer() #begin time measure
        h = SHA512.new(data)
        verifier = DSS.new(key, 'fips-186-3') #verifier uses the public key
        try:
            verifier.verify(h, signature) #data is verified
            end = timer() #end time measure
            #print(end-start) #total execution time
            addition_verify += end - start
            #print("The message is authentic.")
        except ValueError:
            pass
            #print("The message is not authentic.")
        #for i in range(len(signature)):
        #    print('{:0>2X}'.format(signature[i]), end='')
        #print("")
    return addition_sign / counter, addition_verify / counter

"""
This function is used to digitally sign a message using ECDSA with binary field and Koblitz Field
It receives one parameter
1: vectors list 
"""
def doECDSA_BF(vectors):
    counter = 0
    addition_sign = 0
    addition_verify = 0
    private_key = ec.generate_private_key(ec.SECT571K1())
    for vector in vectors:
        counter += 1
        data = bytes.fromhex(vector) #vector is converted from hex to a binary object
        start = timer() #begin time measure
        signature = private_key.sign(data, ec.ECDSA(hashes.SHA256())) #data is signed with private key
        end = timer() #end time measure
        #print(end-start) #total execution time
        addition_sign += end - start
        start = timer() #begin time measure
        public_key = private_key.public_key()
        try:
            public_key.verify(signature, data, ec.ECDSA(hashes.SHA256())) #data is verified with public key
            end = timer() #end time measure
            addition_verify += end - start
            #print(end-start) #total execution time
            #print("The message is authentic.")
        except InvalidSignature:
            pass
            #print("The message is not authentic.")
            
        #for i in range(len(signature)):
        #   print('{:0>2X}'.format(signature[i]), end='')
        #print("")
    
    return addition_sign / counter, addition_verify / counter

# Read vectors for AES, RSA, DSA and ECDSA  
vectors = getVectors("vectors.txt")
# Read vectors for SHA2 and SHA3
hash_vectors = getVectors("hash_vectors.txt")

# All test vector are going to be tested 100 times in each algorithm
rounds = 100

avg_time_AESECB_E = 0           # Stores the average time of encryption using AES-ECB
avg_time_AESCBC_E = 0           # Stores the average time of encryption using AES-CBC
avg_time_RSA_E = 0              # Stores the average time of encryption using RSA-OAEP
avg_time_AESECB_D = 0           # Stores the average time of decryption using AES-ECB
avg_time_AESCBC_D = 0           # Stores the average time of decryption using AES-CBC
avg_time_RSA_D = 0              # Stores the average time of decryption using RSA-OAEP
avg_time_SHA_2_384 = 0          # Stores the average time of hashing using SHA-2-384
avg_time_SHA_2_512 = 0          # Stores the average time of hashing using SHA-2-512
avg_time_SHA_3_384 = 0          # Stores the average time of hashing using SHA-3-384
avg_time_SHA_3_512 = 0          # Stores the average time of hashing using SHA-3-512
avg_time_RSA_S = 0              # Stores the average time of signing using RSA-PSS
avg_time_DSA_S = 0              # Stores the average time of signing using DSA
avg_time_ECDSA_prime_S = 0      # Stores the average time of signing using ECDSA-P521
avg_time_ECDSA_binary_S = 0     # Stores the average time of signing using ECDSA-K571
avg_time_RSA_V = 0              # Stores the average time of verifying using RSA-PSS
avg_time_DSA_V = 0              # Stores the average time of verifying using DSA
avg_time_ECDSA_prime_V = 0      # Stores the average time of verifying using ECDSA-P521
avg_time_ECDSA_binary_V = 0     # Stores the average time of verifying using ECDSA-K571

for i in range(rounds):
    #Encryption
    #AES-ECB256
    avg_time_AESECB_E += doAES(vectors, "ECB", "ENCRYPT")
    #AES-CBC256
    avg_time_AESCBC_E += doAES(vectors, "CBC", "ENCRYPT")
    #RSA
    RSA_Encryption, RSA_Decryption = doRSA(vectors, "OAEP")
    avg_time_RSA_E += RSA_Encryption
   
    #Decryption
    #AES-ECB256
    avg_time_AESECB_D += doAES(vectors, "ECB", "DECRYPT")
    #AES-CBC256
    avg_time_AESCBC_D += doAES(vectors, "CBC", "DECRYPT")
    #RSA
    avg_time_RSA_D += RSA_Decryption

    #Hashing
    #SHA384
    avg_time_SHA_2_384 += doSHA(hash_vectors, 384, 2)
    #SHA512
    avg_time_SHA_2_512 += doSHA(hash_vectors, 512, 2)
    #SHA3_384
    avg_time_SHA_3_384 += doSHA(hash_vectors, 384, 3)
    #SHA3_512
    avg_time_SHA_3_512 += doSHA(hash_vectors, 512, 3)
    
    #Signing and Verifying
    #RSA
    signing_time, verifying_time = doRSA(vectors, "PSS")
    avg_time_RSA_S += signing_time
    avg_time_RSA_V += verifying_time

    #DSA
    signing_time, verifying_time = doDSS(vectors, "DSA")
    avg_time_DSA_S += signing_time
    avg_time_DSA_V += verifying_time

    #ECDSA prime field
    signing_time, verifying_time = doDSS(vectors, "ECDSA")
    avg_time_ECDSA_prime_S += signing_time
    avg_time_ECDSA_prime_V += verifying_time

    #ECDSA binary field
    signing_time, verifying_time = doECDSA_BF(vectors)
    avg_time_ECDSA_binary_S += signing_time
    avg_time_ECDSA_binary_V += verifying_time


print("Rondas: " + str(rounds))
print("Tiempos promedio de cifrado")
print("AES-ECB: " + str(avg_time_AESECB_E / rounds) + " | " + "AES-CBC: " + str(avg_time_AESCBC_E / rounds) + " | " + "RSA-OAEP: " + str(avg_time_RSA_E / rounds))
#print("AES-CBC: " + str(avg_time_AESCBC_E / rounds))
#print("RSA-OAEP: " + str(avg_time_RSA_E / rounds))
print("")
print("Tiempos promedio de descifrado")
print("AES-ECB: " + str(avg_time_AESECB_D / rounds) + " | " + "AES-CBC: " + str(avg_time_AESCBC_D / rounds) + " | " + "RSA-OAEP: " + str(avg_time_RSA_D / rounds))
#print("AES-CBC: " + str(avg_time_AESCBC_D / rounds))
#print("RSA-OAEP: " + str(avg_time_RSA_D / rounds))
print("")
print("Tiempos promedio de hash")
print("SHA2-384: " + str(avg_time_SHA_2_384 / rounds) + " | " + "SHA2-512: " + str(avg_time_SHA_2_512 / rounds) + " | " + "SHA3-384: " + str(avg_time_SHA_3_384 / rounds) + " | " + "SHA3-512: " + str(avg_time_SHA_3_512 / rounds))
#print("SHA2-512: " + str(avg_time_SHA_2_512 / rounds))
#print("SHA3-384: " + str(avg_time_SHA_3_384 / rounds))
#print("SHA3-512: " + str(avg_time_SHA_3_512 / rounds))
print("")
print("Tiempos promedio de firma")
print("RSA-PSS: " + str(avg_time_RSA_S / rounds) + " | " + "DSA: " + str(avg_time_DSA_S / rounds) + " | " + "ECC-P521: " + str(avg_time_ECDSA_prime_S / rounds) + " | " + "ECC-K571: " + str(avg_time_ECDSA_binary_S / rounds))
#print("DSA: " + str(avg_time_DSA_S / rounds))
#print("ECC-P521: " + str(avg_time_ECDSA_prime_S / rounds))
#print("ECC-K571: " + str(avg_time_ECDSA_binary_S / rounds))
print("")
print("Tiempos promedio de verificacion de firma")
print("RSA-PSS: " + str(avg_time_RSA_V / rounds) + " | " + "DSA: " + str(avg_time_DSA_V / rounds) + " | " + "ECC-P521: " + str(avg_time_ECDSA_prime_V / rounds) + " | " + "ECC-K571: " + str(avg_time_ECDSA_binary_V / rounds))
#print("DSA: " + str(avg_time_DSA_V / rounds))
#print("ECC-P521: " + str(avg_time_ECDSA_prime_V / rounds))
#print("ECC-K571: " + str(avg_time_ECDSA_binary_V / rounds))