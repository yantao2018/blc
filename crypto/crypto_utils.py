 
def recover_pubkey(signature, data, check=None, backend=None, curve=ec.SECP256K1()):
    from cryptography.hazmat.backends.openssl.ec import _EllipticCurvePublicKey
    
    backend = backend or default_backend()

    curve_nid = backend._elliptic_curve_to_nid(curve)

    with backend._tmp_bn_ctx() as ctx:
        ec_cdata = backend._lib.EC_KEY_new_by_curve_name(curve_nid)
        backend.openssl_assert(ec_cdata != backend._ffi.NULL)
        ec_cdata = backend._ffi.gc(ec_cdata, backend._lib.EC_KEY_free)
        
        group = backend._lib.EC_KEY_get0_group(ec_cdata)
        backend.openssl_assert(group != backend._ffi.NULL)

        z_data = sha256(data)
        z_len = (backend._lib.EC_GROUP_get_degree(group) + 7) // 8
        backend.openssl_assert(z_len > 0)
        z_buf = backend._ffi.new("unsigned char[]", z_data[-z_len:])
        z = backend._lib.BN_CTX_get(ctx)
        backend._lib.BN_bin2bn(z_buf, z_len, z)
        # print(f'z:     {backend._bn_to_int(z)}')

        sigbuf = backend._ffi.new("unsigned char[]", signature)
        psigbuf = backend._ffi.new("unsigned char **", sigbuf)
        sig = backend._lib.d2i_ECDSA_SIG(backend._ffi.NULL, psigbuf, len(signature))
        backend.openssl_assert(sig != backend._ffi.NULL)

        pr = backend._ffi.new("BIGNUM **")
        ps = backend._ffi.new("BIGNUM **")
        backend._lib.ECDSA_SIG_get0(sig, pr, ps)
        r = backend._bn_to_int(pr[0])
        s = backend._bn_to_int(ps[0])
        # print(f'sig:   {r}\n       {s}')

        for y in [0, 1]:
            point = backend._lib.EC_POINT_new(group)
            backend._lib.EC_POINT_set_compressed_coordinates_GFp(group, point, pr[0], y, ctx)
            bnx = backend._lib.BN_CTX_get(ctx)
            bny = backend._lib.BN_CTX_get(ctx)
            backend._lib.EC_POINT_get_affine_coordinates_GFp(group, point, bnx, bny, ctx)
            # print(f'point: {backend._bn_to_int(bnx)}\n       {backend._bn_to_int(bny)}')

            order = backend._lib.BN_CTX_get(ctx)
            backend._lib.EC_GROUP_get_order(group, order, ctx)
            # print(f'order: {backend._bn_to_int(order)}')

            inv = backend._lib.BN_CTX_get(ctx)
            backend._lib.BN_mod_inverse(inv, pr[0], order, ctx)
            # print(f'r inv: {backend._bn_to_int(inv)}')

            rs = backend._lib.BN_CTX_get(ctx)
            backend._lib.BN_mod_mul(rs, inv, ps[0], order, ctx)
            # print(f'r1 s:  {backend._bn_to_int(rs)}')

            rz = backend._lib.BN_CTX_get(ctx)
            rzn = backend._lib.BN_CTX_get(ctx)
            zero = backend._lib.BN_CTX_get(ctx)
            backend._lib.BN_mod_mul(rz, inv, z, order, ctx)
            backend._lib.BN_mod_sub(rzn, zero, rz, order, ctx)
            # print(f'r1 z:  {backend._bn_to_int(rz)}')
            # print(f'-r1 z: {backend._bn_to_int(rzn)}')

            zn = backend._lib.BN_CTX_get(ctx)
            backend._lib.BN_mod_sub(zn, zero, z, order, ctx)

            res = backend._lib.EC_POINT_new(group)
            backend._lib.EC_POINT_mul(group, res, rzn, point, rs, ctx)
            bnx = backend._lib.BN_CTX_get(ctx)
            bny = backend._lib.BN_CTX_get(ctx)
            backend._lib.EC_POINT_get_affine_coordinates_GFp(group, res, bnx, bny, ctx)
            # print(f'pkey:  {backend._bn_to_int(bnx)}\n       {backend._bn_to_int(bny)}')

            ec_cdata = backend._ec_key_set_public_key_affine_coordinates(ec_cdata, backend._bn_to_int(bnx), backend._bn_to_int(bny))
            evp_pkey = backend._ec_cdata_to_evp_pkey(ec_cdata)

            pkey = _EllipticCurvePublicKey(backend, ec_cdata, evp_pkey)
            
            if not check or check(pkey):
                return pkey
