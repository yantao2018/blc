from typing import Any, Optional, NamedTuple, List, Dict, DefaultDict, Union
from account import Account
from digest import Digest
from transaction import Transaction

class State(DefaultDict[Digest, Account]):
    def __init__(self, default_factory=Account, *args, **kwargs):
        super().__init__(default_factory, *args, **kwargs)

    def apply(self, transaction: Transaction) -> 'State':
        sender = self[transaction.sender]
        recipient = self[transaction.recipient]
        
        # check signature
        try:
            transaction.verify()
        except:
            raise Exception('invalid transaction signature')
        
        # check nonce
        if sender.nonce != transaction.nonce:
            raise Exception('invalid transaction nonce')
        
        # check balance
        if sender.balance < transaction.amount:
            raise Exception('insufficient funds')

        newstate = self.copy()
        sender = newstate[transaction.sender] = sender.copy()
        recipient = newstate[transaction.recipient] = recipient.copy()
        
        # increase nonce, transfer funds
        sender.nonce += 1
        sender.balance -= transaction.amount
        recipient.balance += transaction.amount
        
        return newstate