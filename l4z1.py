from hashlib import md5
from base64 import b64decode
import random
import pickle

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.Util.number import long_to_bytes
import jks



def get_by_alias(password, alias_code, keystore_path):
    keystore = jks.KeyStore.load(keystore_path, password) 
    for alias, keystore in keystore.secret_keys.items():

        if keystore.alias == alias_code:
            return keystore.key



#CBC

def encrypt_cbc(pswrd, plain_text):
    iv = get_random_bytes(AES.block_size)
    cipher = AES.new(pswrd, AES.MODE_CBC, iv)
    return iv + cipher.encrypt(pad(plain_text.encode('utf-8'), AES.block_size))

def decrypt_cbc(pswrd, data):
    file_vector = data[:AES.block_size]
    decryption_cipher = AES.new(pswrd, AES.MODE_CBC, file_vector)
    dec= unpad(decryption_cipher.decrypt(data[AES.block_size:]), AES.block_size)
    return str(dec)[2:-1]


#GCM

def encrypt_gcm(pswrd, plain_text):
    cipher = AES.new(pswrd, AES.MODE_GCM)
    sm = str(plain_text).encode("utf8")
    ciphertext, tag = cipher.encrypt_and_digest(sm)
    enc = cipher.nonce + ciphertext + tag
    return enc 

def decrypt_gcm(pswrd, data):
    cipher = AES.new(pswrd, AES.MODE_GCM, data[:16])
    dec = cipher.decrypt_and_verify(data[16:-16], data[-16:])
    return str(dec)[2:-1]

def gamemode(pswrd, text, encrypt_f, decrypt_f, game):
    text_tab = text.splitlines( )
    print(text_tab)
    if game == 1:
        enc_tab = []
        dec_tab = []
        for i in range(0, len(text_tab)):
            enc = encrypt_f(pswrd, text_tab[i])
            dec = decrypt_f(pswrd, enc)
            enc_tab.append(enc)
            dec_tab.append(dec)
            #print(dec)
        return enc_tab
    if game == 2:
        if len(text_tab) > 1:
            b = random.getrandbits(1)
            enc = encrypt_f(pswrd, text_tab[b])
            dec = decrypt_f(pswrd, enc)
            return enc

def main_program(mode_type, keystore_path, key_alias, text, game):

    passw = input('podaj haslo do keystore:') # hasło to password
    pswrd = get_by_alias(passw, key_alias, keystore_path)
    if mode_type == 'GCM':
        x =gamemode(pswrd, text, encrypt_gcm, decrypt_gcm, game)
    if mode_type == 'CBC':
        x = gamemode(pswrd, text, encrypt_cbc, decrypt_cbc, game)
    print(x)# return x



x_file = './example.pkl'
with open(x_file, 'rb') as f:
    ex_text = pickle.load(f)
#main_program('CBC', 'keystore.jceks', '256bitkey', ex_text, 2)
main_program('GCM', 'keystore.jceks', '256bitkey', ex_text, 1)

# tworzenie przykładowego pliku
#text_to_file = "przykładowy tekst \n podzielony \n na czesci \n znakami nowej lini "
#file = open('./example.pkl', 'wb') 
#pickle.dump(text_to_file, file, protocol=-1)