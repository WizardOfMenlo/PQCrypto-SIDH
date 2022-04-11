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
    return [hex(int.from_bytes(w, 'big')) for w in words]

def intwordify(a: int) -> list[int]:
    words = wordify(a)
    return [int.from_bytes(word, 'big') for word in words]

intg = lambda arr: sum([x * 2**(i*64) for i, x in enumerate(arr)])

def printf2(name: str, el: tuple[int, int]):
    print(f'{name}_0 := ', hexwordify(el[0]))
    print(f'{name}_1 := ', hexwordify(el[1]))

print("--------GF(p)------------");
##### Montgomery ##########
print("--------Montgomery------------");
A = intg([ 0xf615317d451632e2, 0x7b86980a3cbe227c, 0x70bfb1110e18d841, 0x242c0d ])
print('A := ', hexwordify(A))
print('mont(A) := ', hexwordify((A * R) % p))
print("------------------------------");

##### Addition ########
print("--------Addition------------");
A = intg([ 0xe16e8065786a34fb, 0xdda46b85ad1d2ca2, 0xfeab3ed59a76b177, 0x6ef3f5 ])
B = intg([ 0xea079e48252fc8c0, 0x62c3c8f4f9724ca, 0xd6c14ce1c2a1a3ed, 0xf2f40 ])
print('A := ', hexwordify(A))
print('B := ', hexwordify(B))
print('A+B := ', hexwordify((A+B) % p))
print('--------------------------------')

##### Subtraction #######
print("--------Subtraction------------");
A = intg([ 0x4c67a7817ca0e335, 0xac9c083a5b9bfecc, 0xee1b393cc1f5cf53, 0x67a8be ])
B = intg([ 0x24f1b658a54fb123, 0xbf17e254ef808cb5, 0x88c42fad340c02e5, 0x11d5061 ])
print('A := ', hexwordify(A))
print('B := ', hexwordify(B))
print('A-B := ', hexwordify((A-B) % p))
print('--------------------------------')

##### Multiplication ######
print("--------Multiplication------------");
A = intg([ 0x8d5c49d8375822e0, 0x2823d4be2a7ddcd6, 0xe5c42912b9e3c27f, 0x615fcf ])
B = intg([ 0xa7e08ad1522e877b, 0xd00fbf124d15d66, 0x845426284bd86a9a, 0x7d5865 ])
print('A := ', hexwordify(A))
print('B := ', hexwordify(B))
print('A*B := ', hexwordify((A*B) % p))
print('--------------------------------')


##### GF(p^2)
print("--------GF(p^2)------------");
##### Montgomery ##########
print("--------Montgomery------------");
A = (
        intg([ 0xadcfe6472806bd58, 0x92f6d85c35d1a143, 0x18dcf0ee6f0551f, 0x16ad08 ]), 
        intg([ 0x417d57fed0871788, 0x1e6233e754764ff8, 0xab802688dd8f47bc, 0x108bb5d])
)

printf2('A', A)
printf2('mont(A)', ((A[0] * R) %p, (A[1] * R) %p))
print("------------------------------");
##### Addition ##########
print("--------Addition------------");
A = (
        intg([ 0x9a705ca22edf4b30, 0xd6b1511a93efe6ab, 0xc4cb346720b44198, 0x29d3ef ]),
        intg([ 0x417d57fed0871788, 0x1e6233e754764ff8, 0xab802688dd8f47bc, 0x108bb5d])
)

B = (
        intg([ 0x6c76bbc0db4b643a, 0xd3cbf0b6bcff65a2, 0xc914c967cd7b12d9, 0xbbbbf2 ]),
        intg([ 0x9d88869695e962ef, 0xfe39051273bc65e0, 0x11d0fbb0042fb7c8, 0x272c68])
    )

printf2('A', A)
printf2('B', B)
printf2('A+B', ((A[0] + B[0]) %p, (A[1] + B[1]) %p))
print("------------------------------");

##### Subtraction ##########
print("--------Subtraction------------");
A = (
        intg([ 0xc1f5be1f894863c9, 0x96290fa5da7df423, 0xe23a0cd3d0ef9856, 0xdd1a52 ]),
        intg([ 0x1e38c7fa77d23c58, 0x1bf721c561f8b5bc, 0x456f26f28debe6b9, 0xcb4c40])
    )

B = (
        intg([ 0x5e1349a2f511dafc, 0x6b18f62cc4bf0bff, 0x90cc70de047f9686, 0xcd1612 ]),
        intg([ 0x62d46363764f19d5, 0x6aba45499b26936e, 0x63e8d8c43582c0b8, 0x4f58ce])
    )

printf2('A', A)
printf2('B', B)
printf2('A+B', ((A[0] - B[0]) %p, (A[1] - B[1]) %p))
print("------------------------------");

##### Multiplication ##########
print("--------Multiplication------------");
A = (
        intg([ 0xc45af956f825f396, 0xd8f62085d65f808c, 0xc6a5936b1f1ffebc, 0x8c97cb ]),
        intg([ 0x1e6284919d2a9847, 0x76ddb0a289f4c104, 0xdfc7cff76021f2e3, 0xa278f1 ])
    )

B = (
        intg([ 0x725c146e3eb2eaac, 0xe3eed80077fb50d5, 0xcfa10bdec2430fca, 0x5d4383 ]),
        intg([ 0xe79e2b75421708, 0xa0ba6bbee78e2ee, 0x31b760dc852e15e, 0xcff610 ])
    )

printf2('A', A)
printf2('B', B)
printf2('A*B', ((A[0]*B[0] - A[1]*B[1]) %p, (A[0]*B[1] + A[1]*B[0]) %p))
print("------------------------------");
