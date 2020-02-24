#!/usr/bin/env sage

import sys
from sage.all import *

if len(sys.argv) < 5:
    print >> sys.stderr, "Usage: %s <p> <a> <b> <points>..." % sys.argv[0]
    print >> sys.stderr, "Outputs the sum, product, etc of <points> in the 3-over-2 tower"
    sys.exit(1)

 # fp field
p=sage_eval(sys.argv[1]) # prime characteristic p
fp=GF(p)
# print "p:", p

# fp2 field
a=fp(sage_eval(sys.argv[2])) # a must be a quadratic nonresidue modulo p
# print "a:", a

# fp6 field
b0=fp(sage_eval(sys.argv[3]))
b1=fp(sage_eval(sys.argv[4]))
# print "b:", b0, " + ", b1, "u"
if b1.is_zero():
    print >> sys.stderr, "coefficient of u in b cannot be 0"
    sys.exit(1)

# fp6 field irrep
P.<x>=PolynomialRing(fp)
fp6_modulus = P(x^6 - (b0^2 + a*b1^2))
if not b0.is_zero():
    fp6_modulus -= P(2*b0*x^3 - 2*b0^2)
# print "fp6 modulus:", fp6_modulus

fp6.<v>=GF(p^6, modulus=fp6_modulus)

# matrix embedding fp2 into fp6
M = Matrix(fp, [[1, -b0*b1^(-1)], [0, b1]])
# print "M:\n", M
M_inverse = M.inverse()
# print "M_inverse:\n", M_inverse

def print_result(out):

    # python truncates leading 0s
    outlist = out.polynomial().list()
    while len(outlist) < 6:
        outlist.append(0)

    # unpack out0, out1, out2 and map back into fp2
    out0 = M_inverse * vector(fp, [outlist[0], outlist[3]])
    out1 = M_inverse * vector(fp, [outlist[1], outlist[4]])
    out2 = M_inverse * vector(fp, [outlist[2], outlist[5]])

    print out0[0]
    print out0[1]
    print out1[0]
    print out1[1]
    print out2[0]
    print out2[1]

for i in range(5, len(sys.argv), 12):

    # parse in1, in2
    # in00, in01, in02 are in fp2, need to be embedded into fp6
    in00 = M * vector(fp, [sage_eval(sys.argv[i]), sage_eval(sys.argv[i+1])])
    in01 = M * vector(fp, [sage_eval(sys.argv[i+2]), sage_eval(sys.argv[i+3])])
    in02 = M * vector(fp, [sage_eval(sys.argv[i+4]), sage_eval(sys.argv[i+5])])
    in0 = fp6([in00[0], in01[0], in02[0], in00[1], in01[1], in02[1]])

    in10 = M * vector(fp, [sage_eval(sys.argv[i+6]), sage_eval(sys.argv[i+7])])
    in11 = M * vector(fp, [sage_eval(sys.argv[i+8]), sage_eval(sys.argv[i+9])])
    in12 = M * vector(fp, [sage_eval(sys.argv[i+10]), sage_eval(sys.argv[i+11])])
    in1 = fp6([in10[0], in11[0], in12[0], in10[1], in11[1], in12[1]])

    # binary ops
    print_result(in0+in1) # add
    print_result(in0-in1) # sub
    print_result(in0*in1) # mul
    print_result(in0*fp6([in10[0], 0, 0, in10[1], 0, 0])) # mul by fp2 element

    # unary ops ignore in1
    print_result(in0*fp6(v)) # mul by gen (ie. mul by v=(0,1,0) in fp6)
    print_result(in0*in0) # square

    # inv
    if in0==fp6.zero():
        print_result(fp6.zero()) # can't invert 0; just output 0
    else:
        print_result(in0^(-1))
