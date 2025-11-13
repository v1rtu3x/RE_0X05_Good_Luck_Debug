# /helper/enc.py

CORRECT_KEY = b"OpenSesame123!"
FLAG = b"DMI{4nt1_d3bug_byp4553d}"
SALT = b"RE_salt_v1"

def rotl8(x, r):
    r %=8
    return ((x << r) & 0xFF) | (x >> (8 - r)) 

def obf_key(k: bytes) -> bytes:
    out = bytearray()
    for i, b in enumerate(k):
        mask = (i*0x45 + 0x3D) & 0xFF
        out.append(rotl8(b ^ mask, i % 8))
    return bytes(out)

def rc4_ksa(key: bytes):
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) & 0xFF
        S[i], S[j] = S[j], S[i]
    return S

def rc4_prga(S, n):
    i = j = 0
    out = bytearray()
    for _ in range(n):
        i = (i + 1) & 0xFF
        j = (j + S[i]) & 0xFF
        S[i], S[j] = S[j], S[i]
        out.append(S[(S[i] + S[j]) & 0xFF])
    return bytes(out)

def rc4(key: bytes, data:bytes) -> bytes:
    S = rc4_ksa(key)
    ks = rc4_prga(S, len(data))
    return bytes(a ^ b for a,b in zip(data, ks))

key = obf_key(CORRECT_KEY)
flag_ct = rc4(CORRECT_KEY + SALT, FLAG)

def as_c_array(name, bs):
    hexes = ", ".join(f"0x{b:02x}" for b in bs)
    return f"static const unsigned char {name}[] = {{ {hexes} }};\nstatic const size_t {name}_len = sizeof({name});"


print(as_c_array("KEY", key))
print(as_c_array("FLAG_CT", flag_ct))
print(as_c_array("SALT", SALT))
