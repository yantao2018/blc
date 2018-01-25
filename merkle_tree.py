from typing import Any, Optional, NamedTuple, List, Dict, DefaultDict, Union
from digest import Digest
from crypto.blc_sha import BlcSha

class MerkleTree(List[Any]):
    @property
    def hash(self) -> Digest:
        if not self:
            return Digest.zero()

        layer = [BlcSha.sha256(b'\x00', item) for item in self]

        while len(layer) > 1:
            layer = [BlcSha.sha256(b'\x01', *layer[i:i + 2]) for i in range(0, len(layer), 2)]

        return layer[0]