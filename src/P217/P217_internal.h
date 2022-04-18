/********************************************************************************************
* SIDH: an efficient supersingular isogeny cryptography library
* Copyright (c) Microsoft Corporation
*
* Website: https://github.com/microsoft/PQCrypto-SIDH
* Released under MIT license
*
* Abstract: internal header file for P217
*********************************************************************************************/  

#ifndef P217_INTERNAL_H
#define P217_INTERNAL_H

#include "../config.h"
 

#if (TARGET == TARGET_AMD64) || (TARGET == TARGET_ARM64) || (TARGET == TARGET_S390X)
    #define NWORDS_FIELD    4               // Number of words of a 217-bit field element
    #define p217_ZERO_WORDS 1               // Number of "0" digits in the least significant part of p217 + 1     
#elif (TARGET == TARGET_x86) || (TARGET == TARGET_ARM)
    #define NWORDS_FIELD    7
    #define p217_ZERO_WORDS 3
#endif
    

// Basic constants

#define NBITS_FIELD             217
#define MAXBITS_FIELD           256                
#define MAXWORDS_FIELD          ((MAXBITS_FIELD+RADIX-1)/RADIX)     // Max. number of words to represent field elements
#define NWORDS64_FIELD          ((NBITS_FIELD+63)/64)               // Number of 64-bit words of a 217-bit field element 
#define NBITS_ORDER             256
#define NWORDS_ORDER            ((NBITS_ORDER+RADIX-1)/RADIX)       // Number of words of oA and oB, where oA and oB are the subgroup orders of Alice and Bob, resp.
#define NWORDS64_ORDER          ((NBITS_ORDER+63)/64)               // Number of 64-bit words of a 224-bit element 
#define MAXBITS_ORDER           NBITS_ORDER
#define ALICE                   0
#define BOB                     1 
#define OALICE_BITS             110
#define OBOB_BITS               107
#define OBOB_EXPON              67    
// TODO: Fix the masks to zero out the last byte
#define MASK_ALICE              0x3F 
#define MASK_BOB                0x03 
#define PRIME                   p217 
#define PARAM_A                 6  
#define PARAM_C                 1
// Fixed parameters for isogeny tree computation
// TODO: MAX_INT_POINTS_BOB might be a bit too big
#define MAX_INT_POINTS_ALICE    6        
#define MAX_INT_POINTS_BOB      8      
#define MAX_Alice               55
#define MAX_Bob                 67
#define MSG_BYTES               16
#define SECRETKEY_A_BYTES       ((OALICE_BITS + 7) / 8)
#define SECRETKEY_B_BYTES       ((OBOB_BITS - 1 + 7) / 8)
#define FP2_ENCODED_BYTES       2*((NBITS_FIELD + 7) / 8)

// SIDH's basic element definitions and point representations

typedef digit_t felm_t[NWORDS_FIELD];                                 // Datatype for representing 217-bit field elements (256-bit max.)
typedef digit_t dfelm_t[2*NWORDS_FIELD];                              // Datatype for representing double-precision 2x217-bit field elements (2x256-bit max.) 
typedef felm_t  f2elm_t[2];                                           // Datatype for representing quadratic extension field elements GF(p217^2)
        
typedef struct { f2elm_t X; f2elm_t Z; } point_proj;                  // Point representation in projective XZ Montgomery coordinates.
typedef point_proj point_proj_t[1]; 

/**************** Function prototypes ****************/
/************* Multiprecision functions **************/

// 217-bit multiprecision addition, c = a+b
void mp_add217(const digit_t* a, const digit_t* b, digit_t* c);
void mp_add217_asm(const digit_t* a, const digit_t* b, digit_t* c);

// 217-bit multiprecision subtraction, c = a-b+2p or c = a-b+4p
extern void mp_sub217_p2(const digit_t* a, const digit_t* b, digit_t* c);
extern void mp_sub217_p4(const digit_t* a, const digit_t* b, digit_t* c);
void mp_sub217_p2_asm(const digit_t* a, const digit_t* b, digit_t* c); 
void mp_sub217_p4_asm(const digit_t* a, const digit_t* b, digit_t* c); 

// 2x217-bit multiprecision subtraction followed by addition with p217*2^448, c = a-b+(p217*2^448) if a-b < 0, otherwise c=a-b 
void mp_subaddx2_asm(const digit_t* a, const digit_t* b, digit_t* c);
void mp_subadd217x2_asm(const digit_t* a, const digit_t* b, digit_t* c);

// Double 2x217-bit multiprecision subtraction, c = c-a-b, where c > a and c > b
void mp_dblsub217x2_asm(const digit_t* a, const digit_t* b, digit_t* c);

/************ Field arithmetic functions *************/

// Copy of a field element, c = a
void fpcopy217(const digit_t* a, digit_t* c);

// Zeroing a field element, a = 0
void fpzero217(digit_t* a);

// Non constant-time comparison of two field elements. If a = b return TRUE, otherwise, return FALSE
bool fpequal217_non_constant_time(const digit_t* a, const digit_t* b); 

// Modular addition, c = a+b mod p217
extern void fpadd217(const digit_t* a, const digit_t* b, digit_t* c);
extern void fpadd217_asm(const digit_t* a, const digit_t* b, digit_t* c);

// Modular subtraction, c = a-b mod p217
extern void fpsub217(const digit_t* a, const digit_t* b, digit_t* c);
extern void fpsub217_asm(const digit_t* a, const digit_t* b, digit_t* c);

// Modular negation, a = -a mod p217        
extern void fpneg217(digit_t* a);  

// Modular division by two, c = a/2 mod p217.
void fpdiv2_217(const digit_t* a, digit_t* c);

// Modular correction to reduce field element a in [0, 2*p217-1] to [0, p217-1].
void fpcorrection217(digit_t* a);

// 217-bit Montgomery reduction, c = a mod p
void rdc217_asm(digit_t* ma, digit_t* mc);
            
// Field multiplication using Montgomery arithmetic, c = a*b*R^-1 mod p217, where R=2^768
void fpmul217_mont(const digit_t* a, const digit_t* b, digit_t* c);
void fpmul217(const digit_t* a, const digit_t* b, digit_t* c);
void fpmul217_asm(const digit_t* a, const digit_t* b, digit_t* c);
void mul217_asm(const digit_t* a, const digit_t* b, digit_t* c);
   
// Field squaring using Montgomery arithmetic, c = a*b*R^-1 mod p217, where R=2^768
void fpsqr217_mont(const digit_t* ma, digit_t* mc);

// Field inversion, a = a^-1 in GF(p217)
void fpinv217_mont(digit_t* a);

// Field inversion, a = a^-1 in GF(p217) using the binary GCD 
void fpinv217_mont_bingcd(digit_t* a);

// Chain to compute (p217-3)/4 using Montgomery arithmetic
void fpinv217_chain_mont(digit_t* a);

/************ GF(p^2) arithmetic functions *************/
    
// Copy of a GF(p217^2) element, c = a
void fp2copy217(const f2elm_t a, f2elm_t c);

// Zeroing a GF(p217^2) element, a = 0
void fp2zero217(f2elm_t a);

// GF(p217^2) negation, a = -a in GF(p217^2)
void fp2neg217(f2elm_t a);

// GF(p217^2) addition, c = a+b in GF(p217^2)
extern void fp2add217(const f2elm_t a, const f2elm_t b, f2elm_t c);           

// GF(p217^2) subtraction, c = a-b in GF(p217^2)
extern void fp2sub217(const f2elm_t a, const f2elm_t b, f2elm_t c); 

// GF(p217^2) division by two, c = a/2  in GF(p217^2) 
void fp2div2_217(const f2elm_t a, f2elm_t c);

// Modular correction, a = a in GF(p217^2)
void fp2correction217(f2elm_t a);
            
// GF(p217^2) squaring using Montgomery arithmetic, c = a^2 in GF(p217^2)
void fp2sqr217_mont(const f2elm_t a, f2elm_t c);
void fp2sqr217_c0_mont(const digit_t* a, digit_t* c);
void fp2sqr217_c0_asm(const digit_t* a, digit_t* c);
void fp2sqr217_c1_mont(const digit_t* a, digit_t* c);
void fp2sqr217_c1_asm(const digit_t* a, digit_t* c);
 
// GF(p217^2) multiplication using Montgomery arithmetic, c = a*b in GF(p217^2)
void fp2mul217_mont(const f2elm_t a, const f2elm_t b, f2elm_t c);
void fp2mul217_c0_mont(const digit_t* a, const digit_t* b, digit_t* c);
void fp2mul217_c0_asm(const digit_t* a, const digit_t* b, digit_t* c);
void fp2mul217_c1_mont(const digit_t* a, const digit_t* b, digit_t* c);
void fp2mul217_c1_asm(const digit_t* a, const digit_t* b, digit_t* c);

// GF(p217^2) inversion using Montgomery arithmetic, a = (a0-i*a1)/(a0^2+a1^2)
void fp2inv217_mont(f2elm_t a);

// GF(p217^2) inversion, a = (a0-i*a1)/(a0^2+a1^2), GF(p217) inversion done using the binary GCD 
void fp2inv217_mont_bingcd(f2elm_t a);


#endif
