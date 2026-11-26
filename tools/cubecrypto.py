"""Exact port of cubeSQL's encrypt_buffer / decrypt_buffer (CBC + ciphertext
stealing, AES single-block) from the official SDK C_SDK/cubesql.c."""
from Crypto.Cipher import AES

BLOCK = 16


def enc_key(key16):
    return AES.new(bytes(key16[:16]).ljust(16, b'\0'), AES.MODE_ECB)


class Ctx:
    def __init__(self, key, enc=True):
        # key already repeated/truncated to keyLen; AES wants 16/24/32
        self.c = AES.new(bytes(key), AES.MODE_ECB)
        self.enc = enc

    def block(self, b16):
        return self.c.encrypt(bytes(b16)) if self.enc else self.c.decrypt(bytes(b16))


def encrypt_buffer(buf: bytearray, dim: int, random: bytearray, ctx: Ctx):
    """Encrypt buf[:dim] in place (CBC-CTS). random[:16] is the IV.
    Returns (iv_bytes, ciphertext_bytes) where ciphertext length == dim.
    For dim < BLOCK the IV is modified (matches C: random is written back)."""
    dbuf = bytearray(2 * BLOCK)
    dbuf[0:BLOCK] = random[0:BLOCK]
    if dim < BLOCK:
        dbuf[BLOCK:BLOCK + dim] = buf[0:dim]
        for i in range(dim):
            dbuf[i + BLOCK] ^= dbuf[i]
        dbuf[dim:dim + BLOCK] = ctx.block(dbuf[dim:dim + BLOCK])
        iv = bytes(dbuf[0:BLOCK])
        buf[0:dim] = dbuf[BLOCK:BLOCK + dim]
        return iv, bytes(buf[0:dim])

    # dim >= BLOCK
    b1 = dbuf           # list-like view via (base, offset)
    # We emulate pointer math with explicit byte slices.
    # Work on a combined space: dbuf (16) then buf.
    # Represent "b1"/"b2" as (which, off) where which in ('d','b').
    def rd(which, off):
        return dbuf[off:off + BLOCK] if which == 'd' else buf[off:off + BLOCK]

    def wr(which, off, data):
        if which == 'd':
            dbuf[off:off + BLOCK] = data
        else:
            buf[off:off + BLOCK] = data

    b1w, b1o = 'd', 0
    b2w, b2o = 'b', 0
    length = dim
    index = 0
    while True:
        a = bytearray(rd(b1w, b1o))
        b = rd(b2w, b2o)
        for i in range(BLOCK):
            a[i] ^= b[i]
        a = ctx.block(a)
        wr(b1w, b1o, a)
        length -= BLOCK
        if index == 0:
            buf[0:BLOCK] = a
        if length >= BLOCK:
            b2w, b2o = 'b', index * BLOCK
            b1w, b1o = 'b', b2o + BLOCK
        index += 1
        if length < BLOCK:
            break

    if length != 0:
        b3 = bytearray(BLOCK)
        b3[0:length] = buf[index * BLOCK:index * BLOCK + length]
        b1 = rd(b1w, b1o)
        for i in range(length):
            b3[i] ^= b1[i]
        for i in range(length, BLOCK):
            b3[i] = b1[i]
        b3 = ctx.block(b3)
        back = bytes(b1)
        buf[dim - length - BLOCK:dim - length] = b3
        buf[dim - length:dim] = back[0:length]
    return bytes(random[0:BLOCK]), bytes(buf[0:dim])


def decrypt_buffer(buf: bytearray, dim: int, ctx: Ctx) -> int:
    """buf = IV(16) ++ ciphertext. Decrypt in place; plaintext ends up at
    buf[0:dim-16]. Returns plaintext length (dim-16)."""
    if dim < 2 * BLOCK:
        length = dim - BLOCK
        blk = ctx.block(buf[length:length + BLOCK])
        buf[length:length + BLOCK] = blk
        for i in range(length):
            buf[i] ^= buf[i + BLOCK]
        return length

    index = 0
    b1o = 0
    b2o = BLOCK
    length = dim - BLOCK
    while True:
        nextlen = length - BLOCK
        if nextlen > BLOCK:
            nextlen = BLOCK
        bufblk = bytearray(ctx.block(buf[b2o:b2o + BLOCK]))
        if nextlen == 0 or nextlen == BLOCK:
            b1 = buf[b1o:b1o + BLOCK]
            for i in range(BLOCK):
                bufblk[i] ^= b1[i]
            buf[index * BLOCK:index * BLOCK + BLOCK] = bufblk
            index += 1
            length -= BLOCK
            if length == 0:
                return dim - BLOCK
            b1o = b2o
            b2o = b2o + BLOCK
        else:
            length = nextlen
            b3 = bytearray(BLOCK)
            b3[0:length] = buf[b2o + BLOCK:b2o + BLOCK + length]
            for i in range(length):
                bufblk[i] ^= b3[i]
            for i in range(length, BLOCK):
                b3[i] = bufblk[i]
            b3 = bytearray(ctx.block(b3))
            b1 = buf[b1o:b1o + BLOCK]
            for i in range(BLOCK):
                b3[i] ^= b1[i]
            buf[index * BLOCK:index * BLOCK + BLOCK] = b3
            index += 1
            buf[index * BLOCK:index * BLOCK + nextlen] = bufblk[0:nextlen]
            return dim - BLOCK


if __name__ == '__main__':
    import os
    key = os.urandom(16)
    ec = Ctx(key, True)
    dc = Ctx(key, False)
    ok = True
    for n in list(range(1, 80)) + [100, 255, 4096]:
        pt = os.urandom(n)
        iv = bytearray(os.urandom(16))
        buf = bytearray(pt)
        ivout, ct = encrypt_buffer(buf, n, bytearray(iv), ec)
        # wire = iv(16) + ct(n)
        wire = bytearray(ivout + ct)
        plen = decrypt_buffer(wire, len(wire), dc)
        if bytes(wire[:plen]) != pt:
            ok = False
            print(f"MISMATCH n={n}: plen={plen}")
            if n <= 40:
                print(" pt=", pt.hex())
                print(" got=", bytes(wire[:plen]).hex())
            break
    print("ROUNDTRIP OK" if ok else "ROUNDTRIP FAILED")
