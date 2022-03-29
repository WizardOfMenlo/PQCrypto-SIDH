//*******************************************************************************************
// SIDH: an efficient supersingular isogeny cryptography library
// Copyright (c) Microsoft Corporation
//
// Website: https://github.com/microsoft/PQCrypto-SIDH
// Released under MIT license 
//
// Abstract: field arithmetic in x64 assembly for P434 on Linux
//*******************************************************************************************

.intel_syntax noprefix 

// Format function and variable names for Mac OS X
#if defined(__APPLE__)
    #define fmt(f)    _##f
#else
    #define fmt(f)    f
#endif

// Registers that are used for parameter passing:
#define reg_p1  rdi
#define reg_p2  rsi
#define reg_p3  rdx


.text
//***********************************************************************
//  217-bit multiprecision addition
//  Operation: c [reg_p3] = a [reg_p1] + b [reg_p2]
//*********************************************************************** 
.global fmt(mp_add217_asm)
fmt(mp_add217_asm): 
  mov    r8, [reg_p1]
  mov    r9, [reg_p1+8]
  mov    r10, [reg_p1+16]
  mov    r11, [reg_p1+24]
  add    r8, [reg_p2] 
  adc    r9, [reg_p2+8] 
  adc    r10, [reg_p2+16] 
  adc    r11, [reg_p2+24] 
  mov    [reg_p3], r8
  mov    [reg_p3+8], r9
  mov    [reg_p3+16], r10
  mov    [reg_p3+24], r11
  ret


//***********************************************************************
//  Field addition
//  Operation: c [reg_p3] = a [reg_p1] + b [reg_p2]
//*********************************************************************** 
.global fmt(fpadd217_asm)
fmt(fpadd217_asm):
  push   rbx
  
  xor    rax, rax
  // Read into memory and add
  mov    r8, [reg_p1]
  mov    r9, [reg_p1+8]
  mov    r10, [reg_p1+16]
  mov    r11, [reg_p1+24]
  add    r8, [reg_p2] 
  adc    r9, [reg_p2+8] 
  adc    r10, [reg_p2+16] 
  adc    r11, [reg_p2+24] 

  // Read 2 * p217 into memory, subtracting as we go
  mov    rbx, [rip+fmt(p217x2)]
  sub    r8, rbx
  mov    rcx, [rip+fmt(p217x2)+8]
  sbb    r9, rcx
  mov    rdi, [rip+fmt(p217x2)+16]
  sbb    r10, rdi
  mov    rsi, [rip+fmt(p217x2)+24]
  sbb    r11, rsi

  // If we have carry, rax = 0xFFFFFFFFFFFFFFFF else rax = 0x0000000000000000
  // Use this to decide whether to add 2p back or not
  sbb    rax, 0
  and    rbx, rax
  and    rcx, rax
  and    rdi, rax
  and    rsi, rax
  
  add    r8, rbx  
  adc    r9, rcx  
  adc    r10, rcx  
  adc    r11, rdi 
  mov    [reg_p3], r8
  mov    [reg_p3+8], r9 
  mov    [reg_p3+16], r10 
  mov    [reg_p3+24], r11
  
  pop    rbx
  ret


//***********************************************************************
//  Field subtraction
//  Operation: c [reg_p3] = a [reg_p1] - b [reg_p2]
//*********************************************************************** 
.global fmt(fpsub217_asm)
fmt(fpsub217_asm):
  push   r12
  
  xor    rax, rax
  
  // Read into memory, and subtract
  mov    r8, [reg_p1]
  mov    r9, [reg_p1+8]
  mov    r10, [reg_p1+16]
  mov    r11, [reg_p1+24]
  sub    r8, [reg_p2] 
  sbb    r9, [reg_p2+8] 
  sbb    r10, [reg_p2+16] 
  sbb    r11, [reg_p2+24] 

  // Subtract the borrow (same trick as before)
  sbb    rax, 0
  

  // Read into mem
  mov    rcx, [rip+fmt(p217x2)]
  mov    rdi, [rip+fmt(p217x2)+8]
  mov    rsi, [rip+fmt(p217x2)+16]
  mov    r12, [rip+fmt(p217x2)+24]
  
  and    rcx, rax
  and    rdi, rax
  and    rsi, rax  
  and    r12, rax  

  add    r8, rcx  
  adc    r9, rdi  
  adc    r10, rsi  
  adc    r11, r12 

  // Write to mem
  mov    [reg_p3], r8
  mov    [reg_p3+8], r9 
  mov    [reg_p3+16], r10 
  mov    [reg_p3+24], r11 

  pop    r12
  ret


///////////////////////////////////////////////////////////////// MACRO
.macro SUB217_PX  P0
  mov    r8, [reg_p1]
  mov    r9, [reg_p1+8]
  mov    r10, [reg_p1+16]
  mov    r11, [reg_p1+24]
  sub    r8, [reg_p2] 
  sbb    r9, [reg_p2+8] 
  sbb    r10, [reg_p2+16] 
  sbb    r11, [reg_p2+24] 
//TODO: We reuse a register here, do we need to?
  mov    rax, [rip+\P0]
  mov    rdi, [rip+\P0+8]
  mov    rsi, [rip+\P0+16]
  add    r8, rax
  mov    rax, [rip+\P0+24]  
  adc    r9, rdi  
  adc    r10, rsi 
  adc    r11, rax 
  mov    [reg_p3], r8
  mov    [reg_p3+8], r9 
  mov    [reg_p3+16], r10 
  mov    [reg_p3+24], r11
  
.endm


//***********************************************************************
//  Multiprecision subtraction with correction with 2*p217
//  Operation: c [reg_p3] = a [reg_p1] - b [reg_p2] + 2*p217
//*********************************************************************** 
.global fmt(mp_sub217_p2_asm)
fmt(mp_sub217_p2_asm):

  SUB217_PX  fmt(p217x2)
  ret


#ifdef _MULX_
#ifdef _ADX_

///////////////////////////////////////////////////////////////// MACROS
// z = a x bi + z
// Inputs: base memory pointer M1 (a),
//         bi pre-stored in rdx,
//         accumulator z in [Z0:Z1] or [Z0:Z4]
// Output: [Z0:Z1] or [Z0:Z4]
// Temps:  regs T0:T1
/////////////////////////////////////////////////////////////////
.macro MULADD64x256 M1, Z0, Z1, Z2, Z3, Z4, T0, T1, C
    mulx   \T0, \T1, \M1     // A0*B0
    xor    \C, \C
    adox   \Z0, \T1
    adox   \Z1, \T0  
    mulx   \T0, \T1, 8\M1    // A0*B1
    adcx   \Z1, \T1
    adox   \Z2, \T0    
    mulx   \T0, \T1, 16\M1   // A0*B2
    adcx   \Z2, \T1
    adox   \Z3, \T0
    mulx   \T0, \T1, 24\M1   // A0*B3          
    adcx   \Z3, \T1
    adox   \Z4, \T0
    adc    \Z4, 0    
.endm


.macro MULADD64x64 M1, Z0, Z1, T0, T1
    mulx   \T0, \T1, \M1     // A0*B0
    xor    rax, rax
    adox   \Z0, \T1
    adox   \Z1, \T0  
    adcx   \Z1, rax    
.endm


///////////////////////////////////////////////////////////////// MACRO
// z = a x b + c x d (mod p)
// Inputs: base memory pointers M0 (a,c), M1 (b,d)
//         bi pre-stored in rdx,
//         accumulator z in [Z0:Z4], pre-stores a0 x b
// Output: [Z0:Z4]
// Temps:  regs T0:T1
/////////////////////////////////////////////////////////////////
.macro FPDBLMUL256x256 M00, M01, M10, M11, Z0, Z1, Z2, Z3, Z4, T0, T1           
    mov    rdx, \M11    
    MULADD64x256 \M01, \Z0, \Z1, \Z2, \Z3, \Z4, \T0, \T1, rax                
    // [Z1:Z4] <- z = (z0 x p217p1 + z)/2^64
    mov    rdx, \Z0                 // rdx <- z0
    MULADD64x64 [rip+fmt(p217p1)+24], \Z3, \Z4, \T0, \T1
    
    // [Z1:Z4, \Z0] <- z = a01 x a1 + z 
    mov    rdx, 8\M10
    MULADD64x256 \M00, \Z1, \Z2, \Z3, \Z4, \Z0, \T0, \T1, \Z0           
    mov    rdx, 8\M11    
    MULADD64x256 \M01, \Z1, \Z2, \Z3, \Z4, \Z0, \T0, \T1, rax        
    // [Z2:Z4, Z0] <- z = (z0 x p217p1 + z)/2^64
    mov    rdx, \Z1                 // rdx <- z0
    MULADD64x64 [rip+fmt(p217p1)+24], \Z4, \Z0, \T0, \T1
    
    // [Z2:Z4, Z0:Z1] <- z = a02 x a1 + z  
    mov    rdx, 16\M10
    MULADD64x256 \M00, \Z2, \Z3, \Z4, \Z0, \Z1, \T0, \T1, \Z1          
    mov    rdx, 16\M11    
    MULADD64x256 \M01, \Z2, \Z3, \Z4, \Z0, \Z1, \T0, \T1, rax     
    // [Z3:Z4, Z0:Z1] <- z = (z0 x p217p1 + z)/2^64
    mov    rdx, \Z2                // rdx <- z0
    MULADD64x64 [rip+fmt(p217p1)+24], \Z0, \Z1, \T0, \T1
    
    // [Z3:Z4, Z0:Z2] <- z = a03 x a1 + z
    mov    rdx, 24\M10
    MULADD64x256 \M00, \Z3, \Z4, \Z0, \Z1, \Z2, \T0, \T1, \Z2          
    mov    rdx, 24\M11    
    MULADD64x256 \M01, \Z3, \Z4, \Z0, \Z1, \Z2, \T0, \T1, rax     
    // [Z4, Z0:Z2] <- z = (z0 x p217p1 + z)/2^64
    mov    rdx, \Z3                // rdx <- z0
    MULADD64x64 [rip+fmt(p217p1)+24], \Z1, \Z2, \T0, \T1
    pop    \T0
.endm


//***********************************************************************
//  Multiplication in GF(p^2), non-complex part
//  Operation: c [reg_p3] = a0 x b0 - a1 x b1
//  Inputs: a = [a1, a0] stored in [reg_p1] 
//          b = [b1, b0] stored in [reg_p2] 
//  Output: c stored in [reg_p3]
//***********************************************************************
.global fmt(fp2mul434_c0_asm)
fmt(fp2mul434_c0_asm):   
    push   r12 
    mov    rcx, reg_p3
	
	// [rcx0:rcx48] <- 8*p - b1
	mov    r8, [rip+fmt(p434x8)]  
	mov    r9, [rip+fmt(p434x8)+8]   
	mov    r11, [rip+fmt(p434x8)+24]
	mov    r12, [rip+fmt(p434x8)+32] 
	mov    rax, [reg_p2+56]
	mov    rdx, [reg_p2+64]
	mov    r10, r9                 
	sub    r8, rax
    push   r13 
	sbb    r9, rdx
	mov    rax, [reg_p2+72]
	mov    rdx, [reg_p2+80]
	sbb    r10, rax
    push   r14 
	sbb    r11, rdx
	mov    rax, [reg_p2+88]
	mov    rdx, [reg_p2+96]
	mov    r13, [rip+fmt(p434x8)+40]
	mov    r14, [rip+fmt(p434x8)+48]
	mov    [rcx], r8
	sbb    r12, rax
    push   r15 
	sbb    r13, rdx
	mov    rax, [reg_p2+104]
	mov    [rcx+8], r9
	sbb    r14, rax 
	mov    [rcx+16], r10
    
    // [r8:r15] <- z = a0 x b00 - a1 x b10
    mov    rdx, [reg_p2]
    mulx   r9, r8, [reg_p1] 
	mov    [rcx+24], r11      
    xor    rax, rax 
    mulx   r10, r11, [reg_p1+8] 
	mov    [rcx+32], r12     
    adox   r9, r11        
    mulx   r11, r12, [reg_p1+16]
	mov    [rcx+40], r13     
    adox   r10, r12        
    mulx   r12, r13, [reg_p1+24] 
	mov    [rcx+48], r14     
    adox   r11, r13       
    mulx   r13, r14, [reg_p1+32]
    push   rbx 
    adox   r12, r14      
    mulx   r14, r15, [reg_p1+40] 
    push   rbp  
    adox   r13, r15      
    mulx   r15, rbx, [reg_p1+48]   
    adox   r14, rbx 
    adox   r15, rax

	FPDBLMUL448x448 [reg_p1], [reg_p1+56], [reg_p2], [rcx], r8, r9, r10, r11, r12, r13, r14, r15, rbx, rbp
	           
    mov    [rcx+40], r12      
    mov    [rcx+48], r13
    pop    r13
    pop    r12
    ret


//***********************************************************************
//  Multiplication in GF(p^2), complex part
//  Operation: c [reg_p3] = a0 x b1 + a1 x b0
//  Inputs: a = [a1, a0] stored in [reg_p1] 
//          b = [b1, b0] stored in [reg_p2] 
//  Output: c stored in [reg_p3]
//***********************************************************************
.global fmt(fp2mul434_c1_asm)
fmt(fp2mul434_c1_asm): 
    mov    rcx, reg_p3
    
    // [r8:r15] <- z = a0 x b10 + a1 x b00
    mov    rdx, [reg_p2]
    mulx   r9, r8, [reg_p1+56]     // a0 x b10
    xor    rax, rax     
    push   r12 
    mulx   r10, r11, [reg_p1+64]  
    push   r13  
    adox   r9, r11        
    mulx   r11, r12, [reg_p1+72]  
    push   r14  
    adox   r10, r12        
    mulx   r12, r13, [reg_p1+80]  
    push   r15   
    adox   r11, r13       
    mulx   r13, r14, [reg_p1+88] 
    push   rbx    
    adox   r12, r14      
    mulx   r14, r15, [reg_p1+96] 
    push   rbp 
    adox   r13, r15      
    mulx   r15, rbx, [reg_p1+104] 
    adox   r14, rbx 
    adox   r15, rax 

	FPDBLMUL448x448 [reg_p1+56], [reg_p1], [reg_p2], [reg_p2+56], r8, r9, r10, r11, r12, r13, r14, r15, rbx, rbp
                             
    mov    [rcx+40], r12      
    mov    [rcx+48], r13
    pop    r13
    pop    r12
    ret

#else

# error "CONFIGURATION NOT SUPPORTED. TRY USE_MULX=TRUE USE_ADX=TRUE"

#endif

#else

# error "CONFIGURATION NOT SUPPORTED. TRY USE_MULX=TRUE USE_ADX=TRUE"

#endif


///////////////////////////////////////////////////////////////// MACRO
// z = a x b (mod p)
// Inputs: base memory pointers M0 (a), M1 (b)
//         bi pre-stored in rdx,
//         accumulator z in [Z0:Z7], pre-stores a0 x b
// Output: [Z0:Z7]
// Temps:  regs T0:T1
/////////////////////////////////////////////////////////////////
.macro FPMUL448x448 M0, M1, Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7, T0, T1           
    // [Z1:Z7] <- z = (z0 x p434p1 + z)/2^64
    mov    rdx, \Z0                 // rdx <- z0
    MULADD64x256 [rip+fmt(p434p1)+24], \Z3, \Z4, \Z5, \Z6, \Z7, \T0, \T1
    
    // [Z1:Z7, \Z0] <- z = a01 x a1 + z 
    mov    rdx, 8\M0
    MULADD64x448 \M1, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z0, \T0, \T1, \Z0
    // [Z2:Z7, Z0] <- z = (z0 x p434p1 + z)/2^64
    mov    rdx, \Z1                 // rdx <- z0
    MULADD64x256 [rip+fmt(p434p1)+24], \Z4, \Z5, \Z6, \Z7, \Z0, \T0, \T1
    
    // [Z2:Z7, Z0:Z1] <- z = a02 x a1 + z  
    mov    rdx, 16\M0
    MULADD64x448 \M1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z0, \Z1, \T0, \T1, \Z1
    // [Z3:Z7, Z0:Z1] <- z = (z0 x p434p1 + z)/2^64
    mov    rdx, \Z2                // rdx <- z0
    MULADD64x256 [rip+fmt(p434p1)+24], \Z5, \Z6, \Z7, \Z0, \Z1, \T0, \T1
    
    // [Z3:Z7, Z0:Z2] <- z = a03 x a1 + z
    mov    rdx, 24\M0
    MULADD64x448 \M1, \Z3, \Z4, \Z5, \Z6, \Z7, \Z0, \Z1, \Z2, \T0, \T1, \Z2
    // [Z4:Z7, Z0:Z2] <- z = (z0 x p434p1 + z)/2^64
    mov    rdx, \Z3                // rdx <- z0
    MULADD64x256 [rip+fmt(p434p1)+24], \Z6, \Z7, \Z0, \Z1, \Z2, \T0, \T1
    
    // [Z4:Z7, Z0:Z3] <- z = a04 x a1 + z 
    mov    rdx, 32\M0
    MULADD64x448 \M1, \Z4, \Z5, \Z6, \Z7, \Z0, \Z1, \Z2, \Z3, \T0, \T1, \Z3
    // [Z5:Z7, Z0:Z3] <- z = (z0 x p434p1 + z)/2^64
    mov    rdx, \Z4                // rdx <- z0
    MULADD64x256 [rip+fmt(p434p1)+24], \Z7, \Z0, \Z1, \Z2, \Z3, \T0, \T1
    
    // [Z5:Z7, Z0:Z4] <- z = a05 x a1 + z    
    mov    rdx, 40\M0
    MULADD64x448 \M1, \Z5, \Z6, \Z7, \Z0, \Z1, \Z2, \Z3, \Z4, \T0, \T1, \Z4
    // [Z6:Z7, Z0:Z4] <- z = (z0 x p434p1 + z)/2^64
    mov    rdx, \Z5                // rdx <- z0
    MULADD64x256 [rip+fmt(p434p1)+24], \Z0, \Z1, \Z2, \Z3, \Z4, \T0, \T1
    
    // [Z6:Z7, Z0:Z5] <- z = a06 x a1 + z  
    mov    rdx, 48\M0
    MULADD64x448 \M1, \Z6, \Z7, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \T0, \T1, \Z5
    // [Z7, Z0:Z5] <- z = (z0 x p434p1 + z)/2^64
    mov    rdx, \Z6                // rdx <- z0
    MULADD64x256 [rip+fmt(p434p1)+24], \Z1, \Z2, \Z3, \Z4, \Z5, \T0, \T1
.endm


//***********************************************************************
//  Squaring in GF(p^2), non-complex part
//  Operation: c [reg_p2] = (a0+a1) x (a0-a1)
//  Inputs: a = [a1, a0] stored in [reg_p1] 
//  Output: c stored in [reg_p2]
//***********************************************************************
.global fmt(fp2sqr434_c0_asm)
fmt(fp2sqr434_c0_asm):   
    push   r12 

	// a0 + a1
	mov    r8, [reg_p1]
	mov    r9, [reg_p1+8]
	mov    r10, [reg_p1+16]
	mov    r11, [reg_p1+24]
	mov    r12, [reg_p1+32]
	add    r8, [reg_p1+56]
    push   r13
	adc    r9, [reg_p1+64]
	adc    r10, [reg_p1+72]
    push   r14 
	adc    r11, [reg_p1+80]
	adc    r12, [reg_p1+88]
	mov    r13, [reg_p1+40]
	mov    r14, [reg_p1+48]
	adc    r13, [reg_p1+96]
	adc    r14, [reg_p1+104]
	mov    [reg_p2], r8
	mov    [reg_p2+8], r9
	mov    [reg_p2+16], r10
	mov    [reg_p2+24], r11
	mov    [reg_p2+32], r12
	mov    [reg_p2+40], r13
	mov    [reg_p2+48], r14
	
	// a0 - a1 + 4xp434
	mov    rax, [reg_p1]
	mov    r10, [reg_p1+8]
	mov    r12, [reg_p1+16]
	mov    r13, [reg_p1+24]
	mov    r14, [reg_p1+32]
	sub    rax, [reg_p1+56]
	sbb    r10, [reg_p1+64]
	sbb    r12, [reg_p1+72] 
    push   r15 
	sbb    r13, [reg_p1+80]
	sbb    r14, [reg_p1+88]
	mov    r15, [reg_p1+40]
	mov    rcx, [reg_p1+48]
	sbb    r15, [reg_p1+96]
	sbb    rcx, [reg_p1+104]
	add    rax, [rip+fmt(p434x4)]                    
	mov    rdx, [rip+fmt(p434x4)+8]
	adc    r10, rdx
	adc    r12, rdx
	adc    r13, [rip+fmt(p434x4)+24]
	adc    r14, [rip+fmt(p434x4)+32]
	adc    r15, [rip+fmt(p434x4)+40]
	adc    rcx, [rip+fmt(p434x4)+48]
	mov    [reg_p2+56], rax 
    
    // [r8:r15] <- z = a00 x a1
    mov    rdx, r8
    mulx   r9, r8, rax                 
	mov    [reg_p2+64], r10 
    xor    rax, rax   
    push   rbx  
    mulx   r10, r11, r10  
	mov    [reg_p2+72], r12 
    adox   r9, r11        
    mulx   r11, r12, r12 
	mov    [reg_p2+80], r13  
    adox   r10, r12        
    mulx   r12, r13, r13 
	mov    [reg_p2+88], r14  
    adox   r11, r13       
    mulx   r13, r14, r14 
	mov    [reg_p2+96], r15  
    adox   r12, r14      
    mulx   r14, r15, r15  
	mov    [reg_p2+104], rcx 
    adox   r13, r15      
    mulx   r15, rbx, rcx  
    adox   r14, rbx 
    adox   r15, rax 
           
	FPMUL448x448 [reg_p2], [reg_p2+56], r8, r9, r10, r11, r12, r13, r14, r15, rbx, rcx
           
    mov    [reg_p2], r15   
    mov    [reg_p2+8], r8         
    mov    [reg_p2+16], r9         
    mov    [reg_p2+24], r10      
    mov    [reg_p2+32], r11      
    mov    [reg_p2+40], r12      
    mov    [reg_p2+48], r13
    pop    rbx
    pop    r15
    pop    r14
    pop    r13
    pop    r12
    ret


//***********************************************************************
//  Squaring in GF(p^2), complex part
//  Operation: c [reg_p2] = 2a0 x a1
//  Inputs: a = [a1, a0] stored in [reg_p1] 
//  Output: c stored in [reg_p2]
//***********************************************************************
.global fmt(fp2sqr434_c1_asm)
fmt(fp2sqr434_c1_asm):  
    push   r12
	
	mov    r8, [reg_p1]
	mov    r9, [reg_p1+8]
	mov    r10, [reg_p1+16]
	mov    r11, [reg_p1+24]
	mov    r12, [reg_p1+32]
	add    r8, r8
    push   r13 
	adc    r9, r9
	adc    r10, r10
    push   r14 
	adc    r11, r11 
	mov    r13, [reg_p1+40] 
	mov    r14, [reg_p1+48] 
	adc    r12, r12    
    push   r15 
	adc    r13, r13  
    push   rbx 
	adc    r14, r14
	sub    rsp, 56
	mov    [rsp+8], r9
	mov    [rsp+16], r10
    
    // [r8:r15] <- z = a00 x a1
    mov    rdx, r8
    mulx   r9, r8, [reg_p1+56] 
	mov    [rsp+24], r11   
    xor    rax, rax 
    mulx   r10, r11, [reg_p1+64]
	mov    [rsp+32], r12
    adox   r9, r11        
    mulx   r11, r12, [reg_p1+72]
	mov    [rsp+40], r13
    adox   r10, r12        
    mulx   r12, r13, [reg_p1+80] 
	mov    [rsp+48], r14
    adox   r11, r13       
    mulx   r13, r14, [reg_p1+88]
    adox   r12, r14      
    mulx   r14, r15, [reg_p1+96]   
    adox   r13, r15      
    mulx   r15, rbx, [reg_p1+104]  
    adox   r14, rbx 
    adox   r15, rax 

	FPMUL448x448 [rsp], [reg_p1+56], r8, r9, r10, r11, r12, r13, r14, r15, rbx, rcx

	add    rsp, 56
    mov    [reg_p2], r15 
    mov    [reg_p2+8], r8         
    mov    [reg_p2+16], r9         
    mov    [reg_p2+24], r10      
    mov    [reg_p2+32], r11      
    mov    [reg_p2+40], r12      
    mov    [reg_p2+48], r13
    pop    rbx
    pop    r15
    pop    r14
    pop    r13
    pop    r12
    ret


//***********************************************************************
//  Field multiplication in GF(p)
//  Operation: c = a x b mod p
//  Inputs: a stored in [reg_p1], b stored in [reg_p2] 
//  Output: c stored in [reg_p3]
//***********************************************************************
.global fmt(fpmul434_asm)
fmt(fpmul434_asm): 
    mov    rcx, reg_p3
     
    // [r8:r15] <- z = a x b0
    mov    rdx, [reg_p2]
    mulx   r9, r8, [reg_p1]  
    push   r12
    xor    rax, rax 
    mulx   r10, r11, [reg_p1+8]
    push   r13 
    adox   r9, r11        
    mulx   r11, r12, [reg_p1+16]
    push   r14 
    adox   r10, r12        
    mulx   r12, r13, [reg_p1+24]   
    push   r15 
    adox   r11, r13       
    mulx   r13, r14, [reg_p1+32]    
    push   rbx   
    adox   r12, r14      
    mulx   r14, r15, [reg_p1+40]  
    push   rbp
    adox   r13, r15      
    mulx   r15, rbx, [reg_p1+48]  
    adox   r14, rbx 
    adox   r15, rax 

	FPMUL448x448 [reg_p2], [reg_p1], r8, r9, r10, r11, r12, r13, r14, r15, rbx, rbp

    mov    [rcx], r15 
    mov    [rcx+8], r8         
    mov    [rcx+16], r9         
    mov    [rcx+24], r10      
    mov    [rcx+32], r11      
    mov    [rcx+40], r12      
    mov    [rcx+48], r13
    pop    rbp
    pop    rbx
    pop    r15
    pop    r14
    pop    r13
    pop    r12
    ret
