import os
from digest import Digest
from crypto.blc_rsa import BlcRsa
from crypto.blc_ec import BlcEc
    
   
if '__main__' == __name__:
    print('Hello blockchain v0.0.6')
    #print(codecs.encode(sha256('hello'), 'hex'))
    #
    data = b'my message!'
    private_key, public_key = BlcEc.generate_key_pair()
    signature = BlcEc.sign_by_private_key(private_key, data)
    rst = BlcEc.verify_by_public_key(public_key, data, signature)
    print('final rst={0}'.format(rst))
    
    
'''
def t1():
    private_key = ec.generate_private_key(ec.SECP256K1(), backend=default_backend())
    public_key = private_key.public_key()
    data = b'my message!'
    for idx in range(1,5):
        signature = private_key.sign(data, ec.ECDSA(hashes.SHA256()))
        print('{0}:{1}'.format(idx, codecs.encode(signature, 'hex')))
        #
        rst = public_key.verify(signature, data, ec.ECDSA(hashes.SHA256()))
        print('rst{0}:{1}'.format(idx, rst))
    print('^_^ ')
'''    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    