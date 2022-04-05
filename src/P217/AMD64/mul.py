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

a0 = intg(4172967017517061463, 14379429852719655040, 2784329423768121391, 16539254)
a1 = intg(1359301204317365176, 3561917806437325732, 1304080115114587095, 427086)

b0 = intg(8138910811213628759, 16889112102677129756, 9775178075281134859, 10289984)
b1 = intg(11556999288182933142, 14510267568792390824, 12629073132224689369, 7894137)

# Note, in code other way around
a = (a0, a1)
b = (b0, b1)

"""
Compute multiplication in F_p^2 (real part)
a[0]b[0] - a[1]*b[1]
"""
def fp2mul_c0_mont(a : tuple[int, int], b: tuple[int, int]):
    u = 0
    b0_words = intwordify(b[0])
    b1_words = intwordify(8*p - b[1])

    print('Precomputed: ', hexwordify(8*p - b[1]))

    for j in range(0, 4):
        print('---------------------------------------------------------' * 2)
        u = u + b0_words[j] * a[0] + b1_words[j] * a[1]
        print(f'u + b0_{j}*a_0 - b1_{j}*a_1: {hexwordify(u)}')
        q = u % 2**w
        print(f'q: {hex(q)}')
        #u = (u // 2**w) + q * p_hat
        u = (u + q * (p+1)) // 2**64
        print(f'updated u: {hexwordify(u)}')

    print('----------------------------------------------------------' * 2)
    return u

print('Result: ', fp2mul_c0_mont(a, b))
print('Expected: ', ((a0 * b0 - a1 * b1) * R_inv) % p)
