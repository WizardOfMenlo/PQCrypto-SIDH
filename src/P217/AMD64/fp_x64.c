/********************************************************************************************
* SIDH: an efficient supersingular isogeny cryptography library
* Copyright (c) Microsoft Corporation
*
* Website: https://github.com/microsoft/PQCrypto-SIDH
* Released under MIT license 
*
* Abstract: modular arithmetic optimized for x64 platforms for P217
*********************************************************************************************/

#include "../P217_internal.h"
#include "../../internal.h"


// Global constants
extern const uint64_t p217[NWORDS_FIELD];
extern const uint64_t p217p1[NWORDS_FIELD]; 
extern const uint64_t p217x2[NWORDS_FIELD];  
extern const uint64_t p217x4[NWORDS_FIELD];


inline void mp_sub217_p2(const digit_t* a, const digit_t* b, digit_t* c)
{ // Multiprecision subtraction with correction with 2*p, c = a-b+2p.    
#if (OS_TARGET == OS_WIN)
    unsigned int i, borrow = 0;

    for (i = 0; i < NWORDS_FIELD; i++) {
        SUBC(borrow, a[i], b[i], borrow, c[i]); 
    }

    borrow = 0;
    for (i = 0; i < NWORDS_FIELD; i++) {
        ADDC(borrow, c[i], ((digit_t*)p217x2)[i], borrow, c[i]); 
    }
    
#elif (OS_TARGET == OS_NIX)                 
    
    mp_sub217_p2_asm(a, b, c);    

#endif
} 


inline void mp_sub217_p4(const digit_t* a, const digit_t* b, digit_t* c)
{ // Multiprecision subtraction with correction with 4*p, c = a-b+4p.    
#if (OS_TARGET == OS_WIN)
    unsigned int i, borrow = 0;

    for (i = 0; i < NWORDS_FIELD; i++) {
        SUBC(borrow, a[i], b[i], borrow, c[i]); 
    }

    borrow = 0;
    for (i = 0; i < NWORDS_FIELD; i++) {
        ADDC(borrow, c[i], ((digit_t*)p217x4)[i], borrow, c[i]); 
    }
#endif
}


inline void fpadd217(const digit_t* a, const digit_t* b, digit_t* c)
{ // Modular addition, c = a+b mod p217.
  // Inputs: a, b in [0, 2*p217-1] 
  // Output: c in [0, 2*p217-1] 
    
#if (OS_TARGET == OS_WIN)
    unsigned int i, carry = 0;
    digit_t mask;

    for (i = 0; i < NWORDS_FIELD; i++) {
        ADDC(carry, a[i], b[i], carry, c[i]); 
    }

    carry = 0;
    for (i = 0; i < NWORDS_FIELD; i++) {
        SUBC(carry, c[i], ((digit_t*)p217x2)[i], carry, c[i]); 
    }
    mask = 0 - (digit_t)carry;

    carry = 0;
    for (i = 0; i < NWORDS_FIELD; i++) {
        ADDC(carry, c[i], ((digit_t*)p217x2)[i] & mask, carry, c[i]); 
    } 
    
#elif (OS_TARGET == OS_NIX)                 
    
    fpadd217_asm(a, b, c);    

#endif
} 


inline void fpsub217(const digit_t* a, const digit_t* b, digit_t* c)
{ // Modular subtraction, c = a-b mod p217.
  // Inputs: a, b in [0, 2*p217-1] 
  // Output: c in [0, 2*p217-1] 
    
#if (OS_TARGET == OS_WIN)
    unsigned int i, borrow = 0;
    digit_t mask;

    for (i = 0; i < NWORDS_FIELD; i++) {
        SUBC(borrow, a[i], b[i], borrow, c[i]); 
    }
    mask = 0 - (digit_t)borrow;

    borrow = 0;
    for (i = 0; i < NWORDS_FIELD; i++) {
        ADDC(borrow, c[i], ((digit_t*)p217x2)[i] & mask, borrow, c[i]); 
    }
    
#elif (OS_TARGET == OS_NIX)                 
    
    fpsub217_asm(a, b, c);    

#endif
}


inline void fpneg217(digit_t* a)
{ // Modular negation, a = -a mod p217.
  // Input/output: a in [0, 2*p217-1] 
    unsigned int i, borrow = 0;
    
    for (i = 0; i < NWORDS_FIELD; i++) {
        SUBC(borrow, ((digit_t*)p217x2)[i], a[i], borrow, a[i]); 
    }
}


void fpdiv2_217(const digit_t* a, digit_t* c)
{ // Modular division by two, c = a/2 mod p217.
  // Input : a in [0, 2*p217-1] 
  // Output: c in [0, 2*p217-1] 
    unsigned int i, carry = 0;
    digit_t mask;
        
    mask = 0 - (digit_t)(a[0] & 1);    // If a is odd compute a+p217
    for (i = 0; i < NWORDS_FIELD; i++) {
        ADDC(carry, a[i], ((digit_t*)p217)[i] & mask, carry, c[i]); 
    }

    mp_shiftr1(c, NWORDS_FIELD);
}  


void fpcorrection217(digit_t* a)
{ // Modular correction to reduce field element a in [0, 2*p217-1] to [0, p217-1].
    unsigned int i, borrow = 0;
    digit_t mask;

    for (i = 0; i < NWORDS_FIELD; i++) {
        SUBC(borrow, a[i], ((digit_t*)p217)[i], borrow, a[i]); 
    }
    mask = 0 - (digit_t)borrow;

    borrow = 0;
    for (i = 0; i < NWORDS_FIELD; i++) {
        ADDC(borrow, a[i], ((digit_t*)p217)[i] & mask, borrow, a[i]); 
    }
}

#if (OS_TARGET == OS_NIX)

void fp2mul217_c0_mont(const digit_t* a, const digit_t* b, digit_t* c)
{
    fp2mul217_c0_asm(a, b, c);
}


void fp2mul217_c1_mont(const digit_t* a, const digit_t* b, digit_t* c)
{
    fp2mul217_c1_asm(a, b, c);
}


void fp2sqr217_c0_mont(const digit_t* a, digit_t* c)
{
    fp2sqr217_c0_asm(a, c);
}


void fp2sqr217_c1_mont(const digit_t* a, digit_t* c)
{
    fp2sqr217_c1_asm(a, c);
}

void fpmul217(const digit_t* a, const digit_t* b, digit_t* c)
{
    fpmul217_asm(a, b, c);
}

#else

// TODO: Both of these are the old P434, change it P217 (No need really since these are only for not unix)

void mp_mul(const digit_t* a, const digit_t* b, digit_t* c, const unsigned int nwords)
{ // Multiprecision multiply, c = a*b, where lng(a) = lng(b) = nwords.
        
    UNREFERENCED_PARAMETER(nwords);
    digit_t t = 0;
    uint128_t uv = {0};
    unsigned int carry = 0;
        
    MULADD128(a[0], b[0], uv, carry, uv);
    t += carry;
    c[0] = uv[0];
    uv[0] = uv[1];
    uv[1] = t;
    t = 0;
    
    MULADD128(a[0], b[1], uv, carry, uv);
    t += carry;
    MULADD128(a[1], b[0], uv, carry, uv);
    t += carry;
    c[1] = uv[0];
    uv[0] = uv[1];
    uv[1] = t;
    t = 0;
    
    MULADD128(a[0], b[2], uv, carry, uv);
    t += carry;
    MULADD128(a[1], b[1], uv, carry, uv);
    t += carry;
    MULADD128(a[2], b[0], uv, carry, uv);
    t += carry;
    c[2] = uv[0];
    uv[0] = uv[1];
    uv[1] = t;
    t = 0;
    
    MULADD128(a[0], b[3], uv, carry, uv);
    t += carry;
    MULADD128(a[2], b[1], uv, carry, uv);
    t += carry;
    MULADD128(a[1], b[2], uv, carry, uv);
    t += carry;
    MULADD128(a[3], b[0], uv, carry, uv);
    t += carry;
    c[3] = uv[0];
    uv[0] = uv[1];
    uv[1] = t;
    t = 0;
    
    MULADD128(a[0], b[4], uv, carry, uv);
    t += carry;
    MULADD128(a[3], b[1], uv, carry, uv);
    t += carry;
    MULADD128(a[2], b[2], uv, carry, uv);
    t += carry;
    MULADD128(a[1], b[3], uv, carry, uv);
    t += carry;
    MULADD128(a[4], b[0], uv, carry, uv);
    t += carry;
    c[4] = uv[0];
    uv[0] = uv[1];
    uv[1] = t;
    t = 0;
    
    MULADD128(a[0], b[5], uv, carry, uv);
    t += carry;
    MULADD128(a[4], b[1], uv, carry, uv);
    t += carry;
    MULADD128(a[3], b[2], uv, carry, uv);
    t += carry;
    MULADD128(a[2], b[3], uv, carry, uv);
    t += carry;
    MULADD128(a[1], b[4], uv, carry, uv);
    t += carry;
    MULADD128(a[5], b[0], uv, carry, uv);
    t += carry;
    c[5] = uv[0];
    uv[0] = uv[1];
    uv[1] = t;
    t = 0;
    
    MULADD128(a[0], b[6], uv, carry, uv);
    t += carry;
    MULADD128(a[5], b[1], uv, carry, uv);
    t += carry;
    MULADD128(a[4], b[2], uv, carry, uv);
    t += carry;
    MULADD128(a[3], b[3], uv, carry, uv);
    t += carry;
    MULADD128(a[2], b[4], uv, carry, uv);
    t += carry;
    MULADD128(a[1], b[5], uv, carry, uv);
    t += carry;
    MULADD128(a[6], b[0], uv, carry, uv);
    t += carry;
    c[6] = uv[0];
    uv[0] = uv[1];
    uv[1] = t;
    t = 0;
    
    MULADD128(a[6], b[1], uv, carry, uv);
    t += carry;
    MULADD128(a[5], b[2], uv, carry, uv);
    t += carry;
    MULADD128(a[4], b[3], uv, carry, uv);
    t += carry;
    MULADD128(a[3], b[4], uv, carry, uv);
    t += carry;
    MULADD128(a[2], b[5], uv, carry, uv);
    t += carry;
    MULADD128(a[1], b[6], uv, carry, uv);
    t += carry;
    c[7] = uv[0];
    uv[0] = uv[1];
    uv[1] = t;
    t = 0;
    
    MULADD128(a[6], b[2], uv, carry, uv);
    t += carry;
    MULADD128(a[5], b[3], uv, carry, uv);
    t += carry;
    MULADD128(a[4], b[4], uv, carry, uv);
    t += carry;
    MULADD128(a[3], b[5], uv, carry, uv);
    t += carry;
    MULADD128(a[2], b[6], uv, carry, uv);
    t += carry;
    c[8] = uv[0];
    uv[0] = uv[1];
    uv[1] = t;
    t = 0;
    
    MULADD128(a[6], b[3], uv, carry, uv);
    t += carry;
    MULADD128(a[5], b[4], uv, carry, uv);
    t += carry;
    MULADD128(a[4], b[5], uv, carry, uv);
    t += carry;
    MULADD128(a[3], b[6], uv, carry, uv);
    t += carry;
    c[9] = uv[0];
    uv[0] = uv[1];
    uv[1] = t;
    t = 0;
    
    MULADD128(a[6], b[4], uv, carry, uv);
    t += carry;
    MULADD128(a[5], b[5], uv, carry, uv);
    t += carry;
    MULADD128(a[4], b[6], uv, carry, uv);
    t += carry;
    c[10] = uv[0];
    uv[0] = uv[1];
    uv[1] = t;
    t = 0;
    
    MULADD128(a[6], b[5], uv, carry, uv);
    t += carry;
    MULADD128(a[5], b[6], uv, carry, uv);
    t += carry;
    c[11] = uv[0];
    uv[0] = uv[1];
    uv[1] = t;
    
    MULADD128(a[6], b[6], uv, carry, uv);
    c[12] = uv[0];
    c[13] = uv[1];
}


void rdc_mont(digit_t* ma, digit_t* mc)
{ // Montgomery reduction exploiting special form of the prime.
  // mc = ma*R^-1 mod p217x2, where R = 2^448.
  // If ma < 2^448*p217, the output mc is in the range [0, 2*p217-1].
  // ma is assumed to be in Montgomery representation.        
    unsigned int carry;
    digit_t t = 0;
    uint128_t uv = {0};
    
    mc[0] = ma[0];
    mc[1] = ma[1];
    mc[2] = ma[2];
    MUL128(mc[0], ((digit_t*)p217p1)[3], uv);
    ADDC(0, uv[0], ma[3], carry, uv[0]); 
    ADDC(carry, uv[1], 0, carry, uv[1]); 
    mc[3] = uv[0];
    uv[0] = uv[1];
    uv[1] = 0;

    MULADD128(mc[0], ((digit_t*)p217p1)[4], uv, carry, uv);
    MULADD128(mc[1], ((digit_t*)p217p1)[3], uv, carry, uv);
    t += carry;
    ADDC(0, uv[0], ma[4], carry, uv[0]); 
    ADDC(carry, uv[1], 0, carry, uv[1]); 
    t += carry; 
    mc[4] = uv[0];
    uv[0] = uv[1];
    uv[1] = t;
    t = 0;

    MULADD128(mc[0], ((digit_t*)p217p1)[5], uv, carry, uv);
    t += carry;
    MULADD128(mc[1], ((digit_t*)p217p1)[4], uv, carry, uv);
    t += carry;
    MULADD128(mc[2], ((digit_t*)p217p1)[3], uv, carry, uv);
    t += carry;
    ADDC(0, uv[0], ma[5], carry, uv[0]); 
    ADDC(carry, uv[1], 0, carry, uv[1]); 
    t += carry; 
    mc[5] = uv[0];
    uv[0] = uv[1];
    uv[1] = t;
    t = 0;

    MULADD128(mc[0], ((digit_t*)p217p1)[6], uv, carry, uv);
    t += carry;
    MULADD128(mc[1], ((digit_t*)p217p1)[5], uv, carry, uv);
    t += carry;
    MULADD128(mc[2], ((digit_t*)p217p1)[4], uv, carry, uv);
    t += carry;
    MULADD128(mc[3], ((digit_t*)p217p1)[3], uv, carry, uv);
    t += carry;
    ADDC(0, uv[0], ma[6], carry, uv[0]); 
    ADDC(carry, uv[1], 0, carry, uv[1]); 
    t += carry; 
    mc[6] = uv[0];
    uv[0] = uv[1];
    uv[1] = t;
    t = 0;

    MULADD128(mc[1], ((digit_t*)p217p1)[6], uv, carry, uv);
    t += carry;
    MULADD128(mc[2], ((digit_t*)p217p1)[5], uv, carry, uv);
    t += carry;
    MULADD128(mc[3], ((digit_t*)p217p1)[4], uv, carry, uv);
    t += carry;
    MULADD128(mc[4], ((digit_t*)p217p1)[3], uv, carry, uv);
    t += carry;
    ADDC(0, uv[0], ma[7], carry, uv[0]); 
    ADDC(carry, uv[1], 0, carry, uv[1]); 
    t += carry; 
    mc[0] = uv[0];
    uv[0] = uv[1];
    uv[1] = t;
    t = 0;

    MULADD128(mc[2], ((digit_t*)p217p1)[6], uv, carry, uv);
    t += carry;
    MULADD128(mc[3], ((digit_t*)p217p1)[5], uv, carry, uv);
    t += carry;
    MULADD128(mc[4], ((digit_t*)p217p1)[4], uv, carry, uv);
    t += carry;
    MULADD128(mc[5], ((digit_t*)p217p1)[3], uv, carry, uv);
    t += carry;
    ADDC(0, uv[0], ma[8], carry, uv[0]); 
    ADDC(carry, uv[1], 0, carry, uv[1]); 
    t += carry; 
    mc[1] = uv[0];
    uv[0] = uv[1];
    uv[1] = t;
    t = 0;

    MULADD128(mc[3], ((digit_t*)p217p1)[6], uv, carry, uv);
    t += carry;
    MULADD128(mc[4], ((digit_t*)p217p1)[5], uv, carry, uv);
    t += carry;
    MULADD128(mc[5], ((digit_t*)p217p1)[4], uv, carry, uv);
    t += carry;
    MULADD128(mc[6], ((digit_t*)p217p1)[3], uv, carry, uv);
    t += carry;
    ADDC(0, uv[0], ma[9], carry, uv[0]); 
    ADDC(carry, uv[1], 0, carry, uv[1]); 
    t += carry; 
    mc[2] = uv[0];
    uv[0] = uv[1];
    uv[1] = t;
    t = 0;

    MULADD128(mc[4], ((digit_t*)p217p1)[6], uv, carry, uv);
    t += carry;
    MULADD128(mc[5], ((digit_t*)p217p1)[5], uv, carry, uv);
    t += carry;
    MULADD128(mc[6], ((digit_t*)p217p1)[4], uv, carry, uv);
    t += carry;
    ADDC(0, uv[0], ma[10], carry, uv[0]); 
    ADDC(carry, uv[1], 0, carry, uv[1]); 
    t += carry; 
    mc[3] = uv[0];
    uv[0] = uv[1];
    uv[1] = t;
    t = 0;

    MULADD128(mc[5], ((digit_t*)p217p1)[6], uv, carry, uv);
    t += carry;
    MULADD128(mc[6], ((digit_t*)p217p1)[5], uv, carry, uv);
    t += carry;
    ADDC(0, uv[0], ma[11], carry, uv[0]); 
    ADDC(carry, uv[1], 0, carry, uv[1]); 
    t += carry; 
    mc[4] = uv[0];
    uv[0] = uv[1];
    uv[1] = t;
    t = 0;

    MULADD128(mc[6], ((digit_t*)p217p1)[6], uv, carry, uv);
    t += carry;
    ADDC(0, uv[0], ma[12], carry, mc[5]); 
    ADDC(carry, uv[1], ma[13], carry, mc[6]);
}

#endif
