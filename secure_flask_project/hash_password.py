import secrets
from hashlib import pbkdf2_hmac

def safe_password(passwd, salt):

    if type(passwd) != str:
        passwd = passwd.data
        
    pepper = '1a3fec1ded6bc3293a91d1f680ae5ca.,1a5e919f77a21b98ad9.()a483199b38fc51'

    if salt == '1':
        salt = secrets.token_hex(32)

    iterations = 60000

    passwd += pepper

    hashed_passwd = pbkdf2_hmac('sha256', passwd.encode(), salt.encode(), iterations)

    return hashed_passwd, salt
