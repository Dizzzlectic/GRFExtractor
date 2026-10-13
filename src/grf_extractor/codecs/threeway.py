"""ThreeWay encryption and CFB96 for the kRO protected GRF header.

Algorithm adapted from Crypto++'s public-domain implementation:
https://github.com/weidai11/cryptopp/blob/master/3way.cpp
"""
import struct
MASK=0xffffffff

def rol(value,bits):
    value &= MASK
    return ((value << bits)|(value >> (32-bits))) & MASK

def theta(a,b,c):
    mix=rol(a^b^c,16)^rol(a^b^c,8)
    u=((a<<24)^(c>>8)^(b<<8)^(a>>24))&MASK
    v=((b<<24)^(a>>8)^(c<<8)^(b>>24))&MASK
    return ((a^mix^u)&MASK,(b^mix^v)&MASK,(c^mix^(u>>16)^(v<<16))&MASK)

def encrypt_block(key,block):
    if len(key)!=12 or len(block)!=12:raise ValueError('ThreeWay uses 12-byte keys and blocks')
    k0,k1,k2=struct.unpack('>3I',key)
    a,b,c=struct.unpack('>3I',block)
    rc=0x0b0b
    for _ in range(11):
        a,b,c=theta(a^k0^(rc<<16),b^k1,c^k2^rc)
        u,v=rol(a,22),rol(c,1)
        a,c,b=rol(u^(b|~v),1),rol(v^(u|~b),22),(b^(v|~u))&MASK
        rc<<=1
        if rc&0x10000:rc^=0x11011
    return struct.pack('>3I',*theta(a^k0^(rc<<16),b^k1,c^k2^rc))

def decrypt_cfb96(key,iv,ciphertext):
    if len(iv)!=12 or len(ciphertext)%12:raise ValueError('CFB96 requires 12-byte IV and full blocks')
    result=bytearray()
    feedback=iv
    for offset in range(0,len(ciphertext),12):
        block=ciphertext[offset:offset+12]
        stream=encrypt_block(key,feedback)
        result.extend(x^y for x,y in zip(block,stream))
        feedback=block
    return bytes(result)
