from pydantic import BaseModel

class Account(BaseModel):
    balance: int = 0
    nonce: int = 0