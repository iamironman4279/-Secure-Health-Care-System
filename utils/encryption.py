from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA, DSA
from Crypto.Signature import DSS
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
import base64
import hmac
import hashlib


class AESEncryption:
    def __init__(self, key):
        self.key = key.encode('utf-8') if isinstance(key, str) else key
        self.sse_key = get_random_bytes(32)  # Secret key for SSE tokens

    def encrypt(self, data):
        cipher = AES.new(self.key, AES.MODE_EAX)
        nonce = cipher.nonce
        ciphertext, tag = cipher.encrypt_and_digest(data.encode('utf-8'))
        return base64.b64encode(nonce + ciphertext).decode('utf-8')

    def decrypt(self, enc_data):
        enc = base64.b64decode(enc_data)
        nonce = enc[:16]
        ciphertext = enc[16:]
        cipher = AES.new(self.key, AES.MODE_EAX, nonce=nonce)
        return cipher.decrypt(ciphertext).decode('utf-8')

    def generate_sse_token(self, value):
        if not value:
            return None
        value_bytes = value.encode('utf-8')
        token = hmac.new(self.sse_key, value_bytes, hashlib.sha256).hexdigest()
        return token
    
# RSA Key Generation and Encryption
class RSAEncryption:
    def __init__(self):
        self.key = RSA.generate(2048)
        self.public_key = self.key.publickey()

    def encrypt(self, data):
        cipher = PKCS1_OAEP.new(self.public_key)
        return base64.b64encode(cipher.encrypt(data.encode('utf-8'))).decode('utf-8')

    def decrypt(self, enc_data):
        cipher = PKCS1_OAEP.new(self.key)
        return cipher.decrypt(base64.b64decode(enc_data)).decode('utf-8')

# DSA Digital Signature
class DSASignature:
    def __init__(self):
        self.key = DSA.generate(2048)

    def sign(self, data):
        h = SHA256.new(data.encode('utf-8'))
        signer = DSS.new(self.key, 'fips-186-3')
        return base64.b64encode(signer.sign(h)).decode('utf-8')

    def verify(self, data, signature):
        h = SHA256.new(data.encode('utf-8'))
        verifier = DSS.new(self.key.publickey(), 'fips-186-3')
        try:
            verifier.verify(h, base64.b64decode(signature))
            return True
        except ValueError:
            return False