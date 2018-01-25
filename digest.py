
class Digest(bytes):
    @classmethod
    def zero(cls)->'Digest':
        return cls(32)
        
    def __repr__(self) -> str:
        return binascii.hexlify(self).decode('ascii')