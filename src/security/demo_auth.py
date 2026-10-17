"""Memory-hard verifier for the ONE PUBLIC fictional demo credential.

This is not a customer account database. The salt/hash identify a published
test fixture; no submitted password or derived password hash is retained.
"""
import hashlib
import hmac

SCRYPT_N, SCRYPT_R, SCRYPT_P = 32768, 8, 3
SALT = bytes.fromhex('f87321e5c49a960f77a3076f1bdca28d')
VERIFIER = bytes.fromhex('f9f658f950ce89c5c81ef741b9bd66893adf85e96b3510e108fe041c490de3d1')


def verify_demo_password(password):
    if not isinstance(password, str) or not 1 <= len(password) <= 256:
        return False
    try:
        derived = hashlib.scrypt(password.encode('utf-8'), salt=SALT, n=SCRYPT_N,
                                 r=SCRYPT_R, p=SCRYPT_P, dklen=32, maxmem=64*1024*1024)
        return hmac.compare_digest(derived, VERIFIER)
    except UnicodeError:
        return False
