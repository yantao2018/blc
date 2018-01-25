from pydantic import BaseModel
from typing import Any, Optional, NamedTuple, List, Dict, DefaultDict, Union
from block import Block
from state import State
from merkle_tree import MerkleTree
from digest import Digest

class BlockChain(BaseModel):
    blocks: Dict[Digest, Block]
    best_block: Block = None
    next_block: Block = None
    state: State

    @property
    def best_block_hash(self):
        return self.best_block.hash if self.best_block else Digest.zero()
    
    def mine_block(self, beneficiary=None):
        block = self.next_block
        
        if not block:
            block = self.next_block = Block(prev_hash=self.best_block_hash)
        
        if beneficiary:
            block.beneficiary = beneficiary
        
        block.mine()
        
        self.blocks[block.hash] = self.best_block = block
        self.state[block.beneficiary].balance += 100
        self.next_block = None
        
    def add_transaction(self, transaction):
        if not self.next_block:
            self.next_block = Block(prev_hash=self.best_block_hash)
            
        self.state = self.state.apply(transaction)
        self.next_block.transactions.append(transaction)