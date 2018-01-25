import os
import codecs
from digest import Digest
from crypto.blc_rsa import BlcRsa
from crypto.blc_ec import BlcEc
from merkle_tree import MerkleTree
from address import Address
from transaction import Transaction
from account import Account
from state import State
from block import Block
from block_chain import BlockChain
from crypto.crypto_utils import CryptoUtils
import app_model
    
   
if '__main__' == __name__:
    print('Hello blockchain v0.0.7')
    #print(codecs.encode(sha256('hello'), 'hex'))
    #
    data = b'my message!'
    private_key, public_key = BlcEc.generate_key_pair()
    signature = BlcEc.sign_by_private_key(private_key, data)
    rst = BlcEc.verify_by_public_key(public_key, data, signature)
    print('final rst={0}'.format(rst))
    #
    alice = Address()
    app_model.public_keys[alice] = alice.public_key
    print(f'alice:{alice!r}')
    bob = Address()
    app_model.public_keys[bob] = bob.public_key
    print(f'bob:{bob!r}')
    carl = Address()
    app_model.public_keys[carl] = carl.public_key
    print(f'carl:{carl!r}')
    chain = BlockChain(blocks={}, state=State())
    print('block chain:{0}'.format(chain))
    chain.mine_block(beneficiary=alice)
    print(chain.best_block.__json__())
    print('block chain s2:{0}'.format(chain.state))
    # 转账
    transaction = Transaction(sender=alice, recipient=bob, nonce=0, amount=25)
    transaction.sign(alice.private_key)
    chain.add_transaction(transaction)
    print('new state:{0}'.format(chain.state))
    # 
    chain.mine_block(beneficiary=carl)
    print('\r\n\r\n{0}'.format(chain.state))
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    