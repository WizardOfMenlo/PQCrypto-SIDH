# Notes on implementing efficient field arithmetic

In the sequel, we assume that $p$ is of the form $2^e_2 * 3^e_3 - 1$.

A python implementation that can be used to double check is in `mul.py`

## Element representation

First of all, for our parameter set, fields element are represented by 4-words, in big endian (i.e. most significant bits are in the last word). 

## The core algorithm
The core algorithm is as follows. Taken from "Efficient Algorithms for Large Prime Characteristic Fields and Their Application to Bilinear Pairings and Supersingular Isogeny-Based Protocols", and adapted to our parameter set. Essentially, we aim to compute $R^{-1} \sum_i a_i b_i \pmod p$. We denote by $x_{i,j}$ the $j$-th word of $x_i$. The core of the algorithm is:
```
def compute_sum_of_products(a_1, ..., a_t, b_1, ... b_t):
    u = 0
    for j in 0..=3:
        u = u + sum([b_{i,j} * a_i for i in 1..=t]) 
        q = u % 2**64
        u = (u + q * (p+1)) // 2**64
    return u
```
Note that the sum in the first line of the loop will be computed with multiprecision operation (i.e. no modular reductions). The computation in the second line and the third can be done with only a sumadd and some clever register shifting. Here is how this would look (naively):
```
// Assume r0, r1, r2, r3, r4 store u + sum(...)
mov r0, temp
// [r0:r4] = [r0:r4] + r0 * (p+1)
MULADD(r0, (p+1) r0, r1, r2, r3, r4)

// the updated value of u will be in r1, r2, r3, r4, (0 word)
```
and in fact, since $p$ has a special form, we can actually elide that move. Compared to the parameter sets that were already implemented, here we needed to shift by one word instead of three, because of that special modulo form (i.e., for p434 the first 3 words are 0)


## Macros
The workhorse of all multiplication routines are two macros:
1. `MULADD64x192`
2. `MULADD64x256`
Both multiply a single word (which is prestored in `rdx`) with either 3 or 4 words, stored into registers (in fact, one register more which is used to store eventual spillover is used). The first macro is used to compute $u + (p + 1) q$ (where $q$ is a single word) of the Montogmery operation, and it is 192 words since $p+1$ starts with 64 zero bits.
The second operation is used to compute the sum in the initial step of the reduction i.e. $u = u + \sum_i a_i b_i,j$
From an implementation perspective, they are very simple, they just compute schoolbook multplication with the aid of two temporary registers and then sum to the accomulator registers. They also sometime zero one register, which is used in more complex routine to clear the top word after a shift

## Arithmetic over GF(p)
### Addition
Addition comes in two versions, multiprecision and field. 
In multiprecision, no modular reduction occurs, so we simply add the two operands word by word, using `adc` in order to preserve the carry.

In field, we might have a conditional reduction, to avoid branching the strategy is as follows (to compute $a + b$)
1. First, load the words of a into registers
2. Compute $a + b$ using `adc` as in the multiprecision case
3. Load $2p$ into registers, while subtracting to get $a + b - 2p$
4. Subtract (with borrow) 0 from rax, which creates a mask $m$ of zeros or one depending on whether borrow occurred
5. Then, add back $2p ^ m$

### Subtraction
Essentially same as with addition (same trick as well)

### Multiplication
This is simply the main algorithm, applied to the 1-element "sum" $a * b$. We start by precomputing $a * b_0$ and then apply the macro

## Arithmetic over GF(p^2)
### Addition
Addition is simply addition over GF(p), but over both words
### Subtraction
Same as addition
### Multiplication
For multiplication, we do two different operations. Suppose we are 
computing $(a + bi)(c + di)$
1. Real part, we want to compute $ac - bd$
2. Complex part, we want to compute $ad + bc$
In the first case, we cheat a little, we first compute $d' = 8p - d \equiv -d$ and then compute the sum $ac + b d'$ using the "Main trick". Of course, we also still precompute the first sum. 
In the second case, we instead just compute the sum as expected. 


## Debugging

1. Disable benches (or rr will take forever)
2. Build with `make EXTRA_CFLAGS="-O3 -g" tests_p217`
3. Run `rr record ./arith_tests-p217`
4. Run `rr replay`
