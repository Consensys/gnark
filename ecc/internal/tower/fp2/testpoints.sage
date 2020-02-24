#!/usr/bin/env sage

import sys
from sage.all import *

if len(sys.argv) < 3:
    print("Usage: %s <p> <b> <points>..." % sys.argv[0])
    print("Outputs the sum, product, etc of <points> in the degree-2 finite field Z_p / x^2-b")
    sys.exit(1)

p=sage_eval(sys.argv[1]) # prime characteristic p
b=sage_eval(sys.argv[2]) # x^2-b must be irrep modulo p
Fp2.<u> = GF(p^2, modulus=x^2-b)

def print_result(out):

    # python truncates leading 0s
    outlist = out.polynomial().list()
    while len(outlist) < 2:
        outlist.append(0)
    
    print outlist[0]
    print outlist[1]

for i in range(3, len(sys.argv), 4):

    # parse in1, in2
    in1=Fp2(sage_eval(sys.argv[i]) + sage_eval(sys.argv[i+1])*u)
    in2=Fp2(sage_eval(sys.argv[i+2]) + sage_eval(sys.argv[i+3])*u)

    # binary ops
    print_result(in1+in2) # add
    print_result(in1-in2) # sub
    print_result(in1*in2) # mul
    print_result(in1*in2.polynomial().constant_coefficient()) # mul by element

    # unary ops ignore in2
    print_result(in1*in1) # sqr

    # inv
    if in1==Fp2.zero():
        print_result(Fp2.zero()) # can't invert 0; just output 0
    else:
        print_result(in1^(-1))

    print_result(in1.conjugate()) # conjugate