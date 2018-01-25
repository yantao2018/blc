import hashlib

class BlcSha(object):
    @classmethod
    def sha256(cls, *vals) -> Digest:
        ctx = hashlib.sha256()
        for val in vals:
            if isinstance(val, str):
                ctx.update(val.encode('utf8'))
            elif isinstance(val, int):
                ctx.update(val.to_bytes(16, 'big'))
            elif hasattr(val, '__digest__'):
                ctx.update(val.__digest__())
            else:
                ctx.update(val)
        return Digest(ctx.digest())