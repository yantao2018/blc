import msgpack
from pydantic import BaseModel
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from typing import Any, Optional, NamedTuple, List, Dict, DefaultDict, Union
from digest import Digest
#from crypto.crypto_utils import CryptoUtils
import app_model

class Transaction(BaseModel):
    sender: Digest
    recipient: Digest
    nonce: int
    amount: int
    signature: Optional[bytes] = None

    def sign(self, key: ec.EllipticCurvePrivateKey):
        data = msgpack.packb(self.values(exclude={'signature'}))

        self.signature = key.sign(data, ec.ECDSA(hashes.SHA256()))

    def verify(self):
        if not self.signature:
            raise Exception('no signature')

        data = msgpack.packb(self.values(exclude={'signature'}))

        # recover public key from signature, verify that it matches sender
        '''
        public_key = CryptoUtils.recover_pubkey(
            self.signature,
            data,
            check=lambda key: Address(public_key=key) == self.sender
        )
        '''
        public_key = app_model.public_keys[self.sender]

        if not public_key:
            raise Exception('invalid signature')
        
        public_key.verify(self.signature, data, ec.ECDSA(hashes.SHA256()))

    def __digest__(self):
        return msgpack.packb(self.values())