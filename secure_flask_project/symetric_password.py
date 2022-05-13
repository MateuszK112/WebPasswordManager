from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from support_crypto import pad, unpad

aes_key = b'3748hns_MNad1j7i'

def symetric_encode(passwd):
    
    passwd = passwd.encode('utf-8')

    iv = get_random_bytes(AES.block_size)

    aes = AES.new(aes_key, AES.MODE_CBC, iv)
    encrypted = iv + aes.encrypt(pad(passwd, AES.block_size))

    return encrypted

def symetric_decode(encryption):

    iv = encryption[:AES.block_size]

    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    decrypted = unpad(cipher.decrypt(encryption[AES.block_size:]), AES.block_size)

    return decrypted.decode('utf-8')

    
