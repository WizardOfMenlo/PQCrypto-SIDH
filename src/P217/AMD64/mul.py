from math import log2, ceil, floor

e_2 = 110
e_3 = 67
p = 2**e_2 * 3**e_3 - 1

# A word is 64 bits = 8 bytes
w = 64
w_bytes = w // 8
l = ceil(log2(p))
n = ceil(l / w)
z = floor(e_2 / w)

p_hat = (p+1) // 2**(z*w)
R = 2**(n*w)
r = 2**w

R_inv = pow(R, -1, p)

""" Take as input a bits integer, and returns an array of n 64-bit integers
"""
def wordify(a: int) -> list[bytes]:
    bit_len = a.bit_length()  
    word_len = max(ceil(bit_len / w), n)
    bts = a.to_bytes(w_bytes * word_len, 'big')
    intermediate = [bts[i:i+w_bytes] for i in range(0, word_len * w_bytes, w_bytes)]
    intermediate.reverse()
    return intermediate

def hexwordify(a: int) -> list[str]:
    words = wordify(a)
    return ['0x' + w.hex().upper() for w in words]

def intwordify(a: int) -> list[int]:
    words = wordify(a)
    return [int.from_bytes(word, 'big') for word in words]

intg = lambda a,b,c,d: a + b * 2**64 + c * 2**128 + d * 2**192


""" Take two integers, and multiply them using the fast method"""
def multiply_old(a: int, b:int):
    u = 0
    a_words = intwordify(a)
    for j in range(0, 4):
        u = u + a_words[j] * b
        q = u % 2**w
        u = (u + q * (p+1)) // 2**64
    return u

def multiply_optimized(a: int, b:int):
    u = 0
    b_words = intwordify(b)
    for j in range(0, 4):
        print('---------------------------------------------------------' * 2)
        u = u + b_words[j] * a
        print(f'u + b_{j}*a: {hexwordify(u)}')
        q = u % 2**w
        print(f'q: {hex(q)}')
        #u = (u // 2**w) + q * p_hat
        u = (u + q * (p+1)) // 2**64
        print(f'updated u: {hexwordify(u)}')

    print('----------------------------------------------------------' * 2)
    return u

a = 69522047883506212010986737141914104016615145011001412765426725504
b = 19259106569522297679362935343016641397079797733361330119675920947

#print('Computed:', multiply_optimized(a, b))
#print('Actual:', (a * b * R_inv) % p)


target_exp = (p - 3) // 4

def decompose_target(target: int) -> tuple[int, int]:
    max_n = target.bit_length() - 1
    residue = target - 2**max_n

    return (n, residue)

print(decompose_target(target_exp))
