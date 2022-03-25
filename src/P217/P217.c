/********************************************************************************************
* SIDH: an efficient supersingular isogeny cryptography library
* Copyright (c) Microsoft Corporation
*
* Website: https://github.com/microsoft/PQCrypto-SIDH
* Released under MIT license
*
* Abstract: supersingular isogeny parameters and generation of functions for P434
*********************************************************************************************/  

#include "P217_api.h" 
#include "P217_internal.h"
#include "../internal.h"


// Encoding of field elements, elements over Z_order, elements over GF(p^2) and elliptic curve points:
// --------------------------------------------------------------------------------------------------
// Elements over GF(p) and Z_order are encoded with the least significant octet (and digit) located at the leftmost position (i.e., little endian format). 
// Elements (a+b*i) over GF(p^2), where a and b are defined over GF(p), are encoded as {a, b}, with a in the least significant position.
// Elliptic curve points P = (x,y) are encoded as {x, y}, with x in the least significant position. 
// Internally, the number of digits used to represent all these elements is obtained by approximating the number of bits to the immediately greater multiple of 32.
// For example, a 217-bit field element is represented with Ceil(217 / 64) = 4 64-bit digits or Ceil(217 / 32) = 7 32-bit digits.
//
// Curve isogeny system "SIDHp217". Base curve: Montgomery curve By^2 = Cx^3 + Ax^2 + Cx defined over GF(p217^2), where A=6, B=1, C=1 and p217 = 2^110*3^67-1
//
         
const uint64_t p217[NWORDS64_FIELD]              = { 0xFFFFFFFFFFFFFFFF, 0x7BC6BFFFFFFFFFFF, 0xA10872128AF43417, 0x0000000001248A1B };
const uint64_t p217x2[NWORDS64_FIELD]            = { 0xFFFFFFFFFFFFFFFE, 0xF78D7FFFFFFFFFFF, 0x4210E42515E8682E, 0x0000000002491437 };
const uint64_t p217x4[NWORDS64_FIELD]            = { 0xFFFFFFFFFFFFFFFC, 0xEF1AFFFFFFFFFFFF, 0x8421C84A2BD0D05D, 0x000000000492286E };
const uint64_t p217x8[NWORDS64_FIELD]            = { 0xFFFFFFFFFFFFFFF8, 0xDE35FFFFFFFFFFFF, 0x0843909457A1A0BB, 0x00000000092450DD };
const uint64_t p217p1[NWORDS64_FIELD]            = { 0x0000000000000000, 0x7BC6C00000000000, 0xA10872128AF43417, 0x0000000001248A1B };
// TODO: These generator values
// Alice's generator values {XPA0 + XPA1*i, XQA0 + xQA1*i, XRA0 + XRA1*i} in GF(p217^2), expressed in Montgomery representation
const uint64_t A_gen[6*NWORDS64_FIELD]           = { 0x3A02003A41AA5696, 0xC45FFA33715593D5, 0x1A7C6C475E2B2E0C, 0x0000000000DE6060,    // XPA0
                                                     0x8958C2BA90083658, 0xEC55A133854B0C3E, 0x33B603EB1415D88D, 0x00000000007BF805,    // XPA1
                                                     0x787BBD78868288C6, 0x012C095E06EAC0F0, 0x9BA422474C683ED8, 0x0000000000DE59E6,    // XQA0
                                                     0x6A98D37823E89645, 0xEEDAFB39BBE96580, 0x0CE16ADF45A3F745, 0x00000000001A56C5,    // XQA1
                                                     0xA4B7B48E0924477C, 0x15853704165FA336, 0x3ED6AEB532AA92D5, 0x00000000010A3644,    // XRA0
                                                     0x508D0E83E36F5BA7, 0x25076F50184D504D, 0x48526CE8FBADA279, 0x0000000000D50F83 };  // XRA1
// Bob's generator values {XPB0, XQB0, XRB0 + XRB1*i} in GF(p217^2), expressed in Montgomery representation
const uint64_t B_gen[6*NWORDS64_FIELD]           = { 0xF16B8FCD5094FF73, 0xD72945950DEA5A40, 0x5B8051E3F35732C7, 0x0000000001014718,    // XPB0 
                                                     0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,    // XPB1
                                                     0x12D77EE866B12444, 0x186BF7903423F87C, 0xDC061C02B9F702FF, 0x0000000000491891,    // XQB0
                                                     0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,    // XQB1
                                                     0xFF1958F63BDB176A, 0xBCE01B07886DB10A, 0x13656F1F8F35E7B4, 0x0000000000EC1A63,    // XRB0
                                                     0x3EF5FA0BA1CF4046, 0x385756FFBBC0F78C, 0xA6016279207B76B5, 0x00000000004C172A };  // XRB1
// Montgomery constant Montgomery_R2 = (2^256)^2 mod p217
const uint64_t Montgomery_R2[NWORDS64_FIELD]     = { 0x2A732D236E62C233, 0x9B7E8A53EDA2096F, 0xB06C6BF6EE0B9770, 0x00000000002ED0F8 };
// Value one in Montgomery representation = 2^256 mod p217
const uint64_t Montgomery_one[NWORDS64_FIELD]    = { 0x000000E006430584, 0x0BC5000000000000, 0xEDA1260B181CA0F5, 0x000000000011177F };


// Fixed parameters for isogeny tree computation
const unsigned int strat_Alice[MAX_Alice-1] = { 
48, 28, 16, 8, 4, 2, 1, 1, 2, 1, 1, 4, 2, 1, 1, 2, 1, 1, 8, 4, 2, 1, 1, 2, 1, 1, 4, 2, 1, 1, 2, 1, 1, 13, 7, 4, 2, 1, 1, 2, 1, 1, 3, 2, 1, 1, 
1, 1, 5, 4, 2, 1, 1, 2, 1, 1, 2, 1, 1, 1, 21, 12, 7, 4, 2, 1, 1, 2, 1, 1, 3, 2, 1, 1, 1, 1, 5, 3, 2, 1, 1, 1, 1, 2, 1, 1, 1, 9, 5, 3, 2, 1, 1, 
1, 1, 2, 1, 1, 1, 4, 2, 1, 1, 1, 2, 1, 1 };

const unsigned int strat_Bob[MAX_Bob-1] = { 
66, 33, 17, 9, 5, 3, 2, 1, 1, 1, 1, 2, 1, 1, 1, 4, 2, 1, 1, 1, 2, 1, 1, 8, 4, 2, 1, 1, 1, 2, 1, 1, 4, 2, 1, 1, 2, 1, 1, 16, 8, 4, 2, 1, 1, 1, 
2, 1, 1, 4, 2, 1, 1, 2, 1, 1, 8, 4, 2, 1, 1, 2, 1, 1, 4, 2, 1, 1, 2, 1, 1, 32, 16, 8, 4, 3, 1, 1, 1, 1, 2, 1, 1, 4, 2, 1, 1, 2, 1, 1, 8, 4, 2, 
1, 1, 2, 1, 1, 4, 2, 1, 1, 2, 1, 1, 16, 8, 4, 2, 1, 1, 2, 1, 1, 4, 2, 1, 1, 2, 1, 1, 8, 4, 2, 1, 1, 2, 1, 1, 4, 2, 1, 1, 2, 1, 1 };
           
// Setting up macro defines and including GF(p), GF(p^2), curve, isogeny and kex functions
#define fpcopy                        fpcopy217
#define fpzero                        fpzero217
#define fpadd                         fpadd217
#define fpsub                         fpsub217
#define fpneg                         fpneg217
#define fpdiv2                        fpdiv2_217
#define fpcorrection                  fpcorrection217
#define fpmul                         fpmul217
#define fpmul_mont                    fpmul217_mont
#define fpsqr_mont                    fpsqr217_mont
#define fpinv_mont                    fpinv217_mont
#define fpinv_chain_mont              fpinv217_chain_mont
#define fpinv_mont_bingcd             fpinv217_mont_bingcd
#define fp2copy                       fp2copy217
#define fp2zero                       fp2zero217
#define fp2add                        fp2add217
#define fp2sub                        fp2sub217
#define mp_sub_p2                     mp_sub217_p2
#define mp_sub_p4                     mp_sub217_p4
#define sub_p4                        mp_sub_p4
#define fp2neg                        fp2neg217
#define fp2div2                       fp2div2_217
#define fp2correction                 fp2correction217
#define fp2mul_mont                   fp2mul217_mont
#define fp2sqr_mont                   fp2sqr217_mont
#define fp2mul_c0_mont                fp2mul217_c0_mont
#define fp2mul_c1_mont                fp2mul217_c1_mont
#define fp2sqr_c0_mont                fp2sqr217_c0_mont
#define fp2sqr_c1_mont                fp2sqr217_c1_mont
#define fp2inv_mont                   fp2inv217_mont
#define fp2inv_mont_bingcd            fp2inv217_mont_bingcd
#define fpequal_non_constant_time     fpequal217_non_constant_time
#define mp_add_asm                    mp_add217_asm
#define mp_subaddx2_asm               mp_subadd217x2_asm
#define mp_dblsubx2_asm               mp_dblsub217x2_asm
#define crypto_kem_keypair            crypto_kem_keypair_SIKEp217
#define crypto_kem_enc                crypto_kem_enc_SIKEp217
#define crypto_kem_dec                crypto_kem_dec_SIKEp217
#define random_mod_order_A            random_mod_order_A_SIDHp217
#define random_mod_order_B            random_mod_order_B_SIDHp217
#define EphemeralKeyGeneration_A      EphemeralKeyGeneration_A_SIDHp217
#define EphemeralKeyGeneration_B      EphemeralKeyGeneration_B_SIDHp217
#define EphemeralSecretAgreement_A    EphemeralSecretAgreement_A_SIDHp217
#define EphemeralSecretAgreement_B    EphemeralSecretAgreement_B_SIDHp217

#include "../fpx.c"
#include "../ec_isogeny.c"
#include "../sidh.c"    
#include "../sike.c"
