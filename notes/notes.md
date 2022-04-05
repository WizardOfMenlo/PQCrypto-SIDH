# Notes on implementing efficient field arithmetic

In the sequel, we assume that $p$ is of the form $2^e_2 * 3^e_3 - 1$.

A python implementation that can be used to double check is in `mul.py`

## Arithmetic over GF(p)

First of all, for our parameter set, fields element are represented by 4-words, in big endian (i.e. most significant bits are in the last word). 

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

### Macros
The workhorse of all multplication routines are two macros:
1. `MULADD64x192`
2. `MULADD64x256`
Both multiple a single word (which is prestored in `rdx`)



## Debugging

1. Disable benches (or rr will take forever)
2. Build with `make EXTRA_CFLAGS="-O3 -g" tests_p217`
3. Run `rr record ./arith_tests-p217`
4. Run `rr replay`
