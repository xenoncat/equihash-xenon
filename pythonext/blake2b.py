"""
BLAKE2b implementation in pure Python 3.
"""

#
# Written in 2016 by Joris van Rantwijk <joris@jorisvr.nl>
#
# To the extent possible under law, the author(s) have dedicated all
# copyright and related and neighboring rights to this software to
# the public domain worldwide. This software is distributed without
# any warranty.
#
# This program may be used under the terms of the CC0 Public Domain Dedication.
# See <http://creativecommons.org/publicdomain/zero/1.0/>.
#
# This program is partly based on the BLAKE2 reference code by Samual Neves.
# Note however that this program is not part of the official BLAKE2 software
# and the original authors of BLAKE2 are in no way responsible for
# any mistakes in this program.
#
# More information about the BLAKE2 hash function can be found at
# https://blake2.net.
#

import struct


BLAKE2B_BLOCKBYTES = 128
BLAKE2B_OUTBYTES   = 64
BLAKE2B_KEYBYTES   = 64
BLAKE2B_PERSONALBYTES = 16

BLAKE2B_IV = [
  0x6a09e667f3bcc908, 0xbb67ae8584caa73b,
  0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
  0x510e527fade682d1, 0x9b05688c2b3e6c1f,
  0x1f83d9abfb41bd6b, 0x5be0cd19137e2179 ]

BLAKE2B_SIGMA = [ 
  [  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 ] ,
  [ 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 ] ,
  [ 11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4 ] ,
  [  7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8 ] ,
  [  9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13 ] ,
  [  2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9 ] ,
  [ 12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11 ] ,
  [ 13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10 ] ,
  [  6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5 ] ,
  [ 10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13 , 0 ] ,
  [  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 ] ,
  [ 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 ] ]


class Blake2bState:
    """Blake2 state structure."""

    __slots__ = ('h', 't', 'f', 'buf', 'buflen', 'outlen')

    # uint64_t h[8];
    # uint64_t t[2];
    # uint64_t f[2];
    # uint8_t  buf[BLAKE2B_BLOCKBYTES];
    # size_t   buflen;
    # size_t   outlen;
    # uint8_t  last_node;

    def __init__(self, outlen, key, personal):
        """Initialize state structure."""

        keylen = 0 if key is None else len(key)

        self.h = ( [ BLAKE2B_IV[0] ^ (0x01010000) ^ (keylen << 8) ^ outlen ] +
                   BLAKE2B_IV[1:] )

        if personal is not None:
            w = struct.unpack('<2Q', personal)
            self.h[6] ^= w[0]
            self.h[7] ^= w[1]

        self.t = [ 0, 0 ]
        self.f = [ 0, 0 ]

        self.buf = bytearray(BLAKE2B_BLOCKBYTES)
        self.buflen = 0
        self.outlen = outlen

        if keylen > 0:
            block = bytearray(BLAKE2B_BLOCKBYTES)
            block[:keylen] = key
            blake2b_update(self, block)


G_INDEX_MAP = [ 
    (  0,  4,  8, 12),
    (  1,  5,  9, 13),
    (  2,  6, 10, 14),
    (  3,  7, 11, 15),
    (  0,  5, 10, 15),
    (  1,  6, 11, 12),
    (  2,  7,  8, 13),
    (  3,  4,  9, 14) ]


def blake2b_round(r, m, v):
    MASK = (1 << 64) - 1
    for i in range(8):
        (pa, pb, pc, pd) = G_INDEX_MAP[i]
        a = v[pa]
        b = v[pb]
        c = v[pc]
        d = v[pd]
        a = (a + b + m[BLAKE2B_SIGMA[r][2*i+0]]) & MASK
        t = d ^ a
        d = ((t & 0xffffffff) << 32) | (t >> 32)
        c = (c + d) & MASK
        t = b ^ c
        b = ((t & 0xffffff) << 40) | (t >> 24)
        a = (a + b + m[BLAKE2B_SIGMA[r][2*i+1]]) & MASK
        t = d ^ a
        d = ((t & 0xffff) << 48) | (t >> 16)
        c = (c + d) & MASK
        t = b ^ c
        b = ((t & 0x7fffffffffffffff) << 1) | (t >> 63)
        v[pa] = a
        v[pb] = b
        v[pc] = c
        v[pd] = d


def blake2b_compress(state, block): 

    m = struct.unpack('<16Q', block)
    v = state.h + BLAKE2B_IV

    v[12] ^= state.t[0]
    v[13] ^= state.t[1]
    v[14] ^= state.f[0]
    v[15] ^= state.f[1]
 
    for r in range(12):
        blake2b_round(r, m, v)

    for i in range(8):
        state.h[i] ^= v[i] ^ v[i + 8]


def blake2b_update(state, indata):
    """Add input bytes to the hash state."""

    inlen = len(indata)
    p = 0

    left = state.buflen
    fill = BLAKE2B_BLOCKBYTES - left

    if inlen > fill:
        state.buflen = 0
        state.buf[left:] = indata[:fill]
        state.t[0] += BLAKE2B_BLOCKBYTES
        if (state.t[0] >> 64) != 0:
            state.t[0] = 0
            state.t[1] += 1
        blake2b_compress(state, state.buf)
        p += fill

        while inlen - p >  BLAKE2B_BLOCKBYTES:
            state.t[0] += BLAKE2B_BLOCKBYTES
            if (state.t[0] >> 64) != 0:
                state.t[0] = 0
                state.t[1] += 1
            blake2b_compress(state, indata[p:p+BLAKE2B_BLOCKBYTES])
            p += BLAKE2B_BLOCKBYTES

    state.buf[state.buflen:state.buflen+inlen-p] = indata[p:]
    state.buflen += inlen - p


def blake2b_final(state):
    """Generate final hash digest."""

    assert state.f[0] == 0

    state.t[0] += state.buflen
    if (state.t[0] >> 64) != 0:
        state.t[0] = 0
        state.t[1] += 1

    state.f[0] = (1 << 64) - 1

    state.buf[state.buflen:] = bytearray(BLAKE2B_BLOCKBYTES - state.buflen)
    blake2b_compress(state, state.buf)

    buf = struct.pack('<8Q', *state.h)
    return bytes(buf[:state.outlen])
    
 
def blake2b(outlen, indata, key=None, personal=None):
    """Compute BLAKE2b hash digest.

    outlen      (int)   -- output length in bytes
    indata      (bytes) -- input data
    key         (bytes) -- optional hash key
    personal    (bytes) -- optional 16-byte tweak

    Return the hash value as a bytes object.
    """

    assert outlen > 0 and outlen <= BLAKE2B_OUTBYTES
    assert key is None or len(key) <= BLAKE2B_KEYBYTES
    assert personal is None or len(personal) == BLAKE2B_PERSONALBYTES

    state = Blake2bState(outlen, key, personal)
    blake2b_update(state, indata)
    return blake2b_final(state)


def main():
    """Run a few testvectors."""

    testvectors = [
        ('',
         '',
         '2e'),
        ('',
         '',
         '0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8'),
        ('00',
         '',
         '03170a2e7597b7b7e3d84c05391d139a62b157e78786d8c082f29dcf4c111314'),
        ('00010203040506070809ff',
         '',
         '2abafe19cab8000c4d56c325408bbe6bb53cdae7abc194f13ed3a49b567292d6'),
        ('',
         '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f',
         '10ebb67700b1868efb4417987acf4690ae9d972fb7a590c2f02871799aaa4786b5e996e8f0f4eb981fc214b005f42d2ff4233499391653df7aefcbc13fc51568'),
        ('00',
         '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f',
         '961f6dd1e4dd30f63901690c512e78e4b45e4742ed197c3c5e45c549fd25f2e4187b0bc9fe30492b16b0d0bc4ef9b0f34c7003fac09a5ef1532e69430234cebd'),
        ('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0',
         '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f',
         'da24bede383666d563eeed37f6319baf20d5c75d1635a6ba5ef4cfa1ac95487e96f8c08af600aab87c986ebad49fc70a58b4890b9c876e091016daf49e1d322e') ]

    print("Running test vectors ...")
    nfail = 0

    for (inhex, keyhex, hashhex) in testvectors:

        print("in:    ", inhex)
        print("key:   ", keyhex)
        print("expect:", hashhex)

        inlen  = len(inhex) // 2
        keylen = len(keyhex) // 2
        outlen = len(hashhex) // 2

        indata = bytes([ int(inhex[2*i:2*i+2], 16) for i in range(inlen) ])
        key    = bytes([ int(keyhex[2*i:2*i+2], 16) for i in range(keylen) ])
        expect = bytes([ int(hashhex[2*i:2*i+2], 16) for i in range(outlen) ])

        digest = blake2b(outlen, indata, key)
        print("result:", ''.join([ '%02x' % t for t in digest ]))
        assert len(digest) == outlen
        if digest != expect:
            print("FAILED")
            nfail += 1

        print()

    print(nfail, "tests failed")
    assert nfail == 0


if __name__ == '__main__':
    main()

