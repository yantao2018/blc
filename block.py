from pydantic import BaseModel
from digest import Digest
from merkle_tree import MerkleTree
from crypto.blc_sha import BlcSha

class Block(BaseModel):
    prev_hash: Digest = Digest.zero()
    nonce: int = 0
    beneficiary: Digest = Digest.zero()
    transactions: MerkleTree

    def __init__(self, *args, **kwargs):
        kwargs.setdefault('transactions', MerkleTree())
        super().__init__(*args, **kwargs)

    def __json__(self):
        return dict(self.values(), hash=self.hash)
        
    @property
    def hash(self) -> Digest:
        return BlcSha.sha256(self.prev_hash, self.nonce, self.beneficiary, self.transactions.hash)

    @property
    def is_valid(self) -> bool:
        return self.hash.startswith(b'\x00')
    
    def mine(self):
        while not self.is_valid:
            self.nonce += 1