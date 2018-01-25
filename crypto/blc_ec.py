import codecs
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

class BlcEc(object):
    @classmethod
    def generate_key_pair(cls):
        private_key = ec.generate_private_key(ec.SECP256K1(), backend=default_backend())
        public_key = private_key.public_key() 
        return private_key, public_key
        
        
        
    @classmethod
    def sign_by_private_key(cls, private_key, data):
        return private_key.sign(data, ec.ECDSA(hashes.SHA256()))
    
    @classmethod
    def verify_by_public_key(cls, public_key, data, signature):
        rst = False
        try:
            public_key.verify(signature, data, ec.ECDSA(hashes.SHA256()))
            rst = True
        except Exception:
            rst = False
        return rst