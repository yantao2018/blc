from pydantic import BaseModel
from typing import Any, Optional, NamedTuple, List, Dict, DefaultDict, Union
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from digest import Digest
from crypto.blc_sha import BlcSha

class Address(Digest):
    private_key: Optional[ec.EllipticCurvePrivateKey] = None
    public_key: Optional[ec.EllipticCurvePublicKey] = None

    def __new__(cls, private_key=None, public_key=None):
        if not public_key and not private_key:
            # generate keypair
            private_key = ec.generate_private_key(ec.SECP256K1(), backend=default_backend())
            public_key = private_key.public_key()
        elif private_key:
            public_key = private_key.public_key()

        # address is SHA-256 of public key
        result = super().__new__(cls, BlcSha.sha256(public_key.public_numbers().encode_point()))
        result.private_key = private_key
        result.public_key = public_key
        return result