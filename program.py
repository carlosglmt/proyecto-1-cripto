import sys
import fileinput
from Crypto.Cipher import AES

def doAES(filename, decryption_mode=False):
    line_counter = 0
    for line in fileinput.input(filename):
        if line_counter == 0:
            key = bytearray.fromhex(line.rstrip())
        elif line_counter == 1:
            data = bytearray.fromhex(line.rstrip())
            if decryption_mode == False:
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
    
"""
AES-ECB256 BLOCK 128bits
ENCRYPT
Linea 0: llave
Linea 1: plaintext
Linea 2: ciphertext
"""
#doAES("./AES-ECB-256/CIFRADO/vectores", True)
"""
AES-ECB256 BLOCK 128bits
DECRYPT
Linea 0: llave
Linea 1: ciphertext
Linea 2: plaintext
"""
#doAES("./AES-ECB-256/DESCIFRADO/vectores", True)