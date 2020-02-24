#!/usr/bin/env sage

import sys
from sage.all import *

if len(sys.argv) < 3:
    print >> sys.stderr, "Usage: %s <x> <b> <points>..." % sys.argv[0]
    print >> sys.stderr, "Outputs operations on <points> in G1"
    sys.exit(1)

# BLS12 parameter x
x=sage_eval(sys.argv[1])
print "x:", x

# BLS12 coefficient b
b=sage_eval(sys.argv[2])
print "b:", b

# subgroup size r
r=x^4-x^2+1
print "r:", r

# fp field
p = (x-1)^2 * r / 3 + x
Fp=GF(p)
print "p:", p

# elliptic curve
E=EllipticCurve(Fp, [0,b])

def print_result(out):
    print out[0]
    print out[1]
    print out[2]

for i in range(3, len(sys.argv), 6):

    # parse in0, in1
    in0 = E([Fp(sage_eval(sys.argv[i])), Fp(sage_eval(sys.argv[i+1])), Fp(sage_eval(sys.argv[i+2]))])
    print "in0:", in0
    # in1 = E([Fp(sage_eval(sys.argv[i+3])), Fp(sage_eval(sys.argv[i+4])), Fp(sage_eval(sys.argv[i+5]))])
    # print "in1:", in1

    # binary ops
    # print_result(in0+in1) # add

    # unary ops ignore in1
    print_result(2*in0) # double