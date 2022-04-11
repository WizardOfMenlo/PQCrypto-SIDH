
#include "../src/config.h"
#include "../src/P217/P217_internal.h"
#include "../src/internal.h"
#include "test_extras.h"
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

void print_digit_t(digit_t digits[NWORDS_FIELD]) {
    for (int i = 0; i < NWORDS_FIELD - 1; i++) {
        printf("0x%lx, ", digits[i]);
    }
    printf("0x%lx", digits[NWORDS_FIELD - 1]);
}


void print_element_f(char* name, felm_t a) {
    printf("%s := [ ", name);
    print_digit_t((digit_t*) a);
    printf(" ]\n");
}

void print_element_f2(char* name, f2elm_t a) {
    printf("%s_%d := [ ", name, 0);
    print_digit_t((digit_t*) &(a[0]));
    printf(" ]\n");
    printf("%s_%d := [ ", name, 1);
    print_digit_t((digit_t*) &(a[1]));
    printf(" ]\n");
}

void fp_check_with_known() {
    felm_t a, b, ma, mb, mr, r;
    printf("--------GF(p)------------\n");

    // Montgomery Conversion
    fprandom217_test((digit_t*) a);

    to_mont(a, ma);

    printf("--------Montgomery------------\n");
    print_element_f("A", a);
    print_element_f("mont(A)", ma);
    printf("------------------------------\n");

    // Test Addition ---------
    fprandom217_test((digit_t*) a);
    fprandom217_test((digit_t*) b);

    to_mont(a, ma);
    to_mont(b, mb);

    fpadd217(ma, mb, mr);
    
    from_mont(mr, r);
    fpcorrection217(r);
    
    printf("--------Addition------------\n");
    print_element_f("A", a);
    print_element_f("B", b);
    print_element_f("A+B", r);
    printf("------------------------------\n");
    
    // Test Subtraction
    fprandom217_test((digit_t*) a);
    fprandom217_test((digit_t*) b);

    to_mont(a, ma);
    to_mont(b, mb);

    fpsub217(ma, mb, mr);
    
    from_mont(mr, r);
    fpcorrection217(r);
    
    printf("--------Subtraction------------\n");
    print_element_f("A", a);
    print_element_f("B", b);
    print_element_f("A-B", r);
    printf("------------------------------\n");
    
    // Test Multiplication 
    fprandom217_test((digit_t*) a);
    fprandom217_test((digit_t*) b);

    to_mont(a, ma);
    to_mont(b, mb);

    fpmul217(ma, mb, mr);
    
    from_mont(mr, r);
    fpcorrection217(r);
    
    printf("--------Multiplication------------\n");
    print_element_f("A", a);
    print_element_f("B", b);
    print_element_f("A*B", r);
    printf("------------------------------\n");
}



void fp2_check_with_known() {
    f2elm_t a, b, ma, mb, mr, r;
    printf("--------GF(p^2)------------\n");

    // Montgomery Conversion
    fp2random217_test((digit_t*) a);

    to_fp2mont(a, ma);

    printf("--------Montgomery------------\n");
    print_element_f2("A", a);
    print_element_f2("mont(A)", ma);
    printf("------------------------------\n");

    // Test Addition ---------
    fprandom217_test((digit_t*) a);
    fprandom217_test((digit_t*) b);

    to_fp2mont(a, ma);
    to_fp2mont(b, mb);

    fp2add217(ma, mb, mr);
    
    from_fp2mont(mr, r);
    fp2correction217(r);
    
    printf("--------Addition------------\n");
    print_element_f2("A", a);
    print_element_f2("B", b);
    print_element_f2("A+B", r);
    printf("------------------------------\n");
    
    // Test Subtraction
    fp2random217_test((digit_t*) a);
    fp2random217_test((digit_t*) b);

    to_fp2mont(a, ma);
    to_fp2mont(b, mb);

    fp2sub217(ma, mb, mr);
    
    from_fp2mont(mr, r);
    fp2correction217(r);
    
    printf("--------Subtraction------------\n");
    print_element_f2("A", a);
    print_element_f2("B", b);
    print_element_f2("A-B", r);
    printf("------------------------------\n");
    
    // Test Multiplication 
    fp2random217_test((digit_t*) a);
    fp2random217_test((digit_t*) b);

    to_fp2mont(a, ma);
    to_fp2mont(b, mb);

    fp2mul217_mont(ma, mb, mr);
    
    from_fp2mont(mr, r);
    fp2correction217(r);
    
    printf("--------Multiplication------------\n");
    print_element_f2("A", a);
    print_element_f2("B", b);
    print_element_f2("A*B", r);
    printf("------------------------------\n");
}

int main() {
    srand(0xdeadbeef);
    fp_check_with_known();
    fp2_check_with_known();
}

