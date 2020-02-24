#!/usr/bin/env sage

import sys
from sage.all import *

if len(sys.argv) < 7:
    print >> sys.stderr, "Usage: %s <t> <p> <r> <a> <b> <points>..." % sys.argv[0]
    print >> sys.stderr, "Outputs the sum, product, etc of <points> in the 2-over-3-over-2 tower"
    print >> sys.stderr, "Assume that fp12.modulus is w^2-(0+v+0v^2+...+0v^5)"
    sys.exit(1)

# BLS12 parameter t
t=sage_eval(sys.argv[1])

# fp field
p=sage_eval(sys.argv[2]) # prime characteristic p
fp=GF(p)
# print "p:", p

P.<x>=PolynomialRing(fp)

# subgroup order r
r=sage_eval(sys.argv[3])
# print "r:", r

# final exponent: (p^12-1)/r
exponent = (p^12 - 1)/r
# print "exponent:", exponent

# fp2 field
a=fp(sage_eval(sys.argv[4])) # a must be a quadratic nonresidue modulo p
fp2_modulus = P(x^2 - a)
fp2.<u>=GF(p^2, modulus=fp2_modulus)
# print "a:", a

# fp6 field
b0=fp(sage_eval(sys.argv[5]))
b1=fp(sage_eval(sys.argv[6]))
b=fp2([b0, b1])
# print "b:", b
binv=b^-1
# print "binv:", binv
if b1.is_zero():
    print >> sys.stderr, "coefficient of u in b cannot be 0"
    sys.exit(1)

# fp12 field irrep
fp12_modulus = P(x^12 - (b0^2 + a*b1^2))
if not b0.is_zero():
    fp12_modulus -= P(2*b0*x^6 - 2*b0^2)
# print "fp12 modulus:", fp12_modulus

fp12.<w>=GF(p^12, modulus=fp12_modulus)

# matrix embedding fp2 into fp6
M = Matrix(fp, [[1, -b0*b1^(-1)], [0, b1]])
# print "M:\n", M
M_inverse = M.inverse()
# print "M_inverse:\n", M_inverse

def embed_perm(elms):
    # this permutation embeds 6 fp2 elements into one fp12 element and vice versa
    # print "elms:", elms
    result = []
    for j in range(2):
        for k in range(0,5,2):
            for l in range(0,7,6):
                result.append(elms[j+k+l])
    # print "perm:", result
    return result

def field_to_list(f):
    # python truncates leading 0s
    flist = f.polynomial().list()
    while len(flist) < 12:
        flist.append(0)
    return flist

def print_result(out):

    outlist = field_to_list(out)

    # unpack fp12 back into 6 fp2 elements
    outs = embed_perm(outlist)
    for j in range(0,12,2):
        out = M_inverse * vector(fp, [outs[j], outs[j+1]])
        print out[0]
        print out[1]

def parse_input(inputs):
    # inputs are in fp2, need to be embedded into fp12
    infp2s = []
    for j in range(0,12,2):
        infp2s += (M * vector(fp, [sage_eval(inputs[j]), sage_eval(inputs[j+1])])).list()
    return fp12(embed_perm(infp2s))

for i in range(7, len(sys.argv), 24):

    # parse in0, in1
    in0 = parse_input(sys.argv[i:i+12])
    in1 = parse_input(sys.argv[i+12:i+24])

    # binary ops
    print_result(in0+in1) # add
    print_result(in0-in1) # sub
    print_result(in0*in1) # mul

    # prepare in1v
    in1v = ["0"]*12
    in1v[2]=sys.argv[i+14]
    in1v[3]=sys.argv[i+15]
    in1v = parse_input(in1v)

    print_result(in0*in1v) # mul by v

    # prepare in1vw
    in1vw = ["0"]*12
    in1vw[8]=sys.argv[i+20]
    in1vw[9]=sys.argv[i+21]
    in1vw = parse_input(in1vw)
    
    print_result(in0*in1vw) # mul by vw

    # prepare in1v2w
    in1v2w = ["0"]*12
    in1v2w[10]=sys.argv[i+22]
    in1v2w[11]=sys.argv[i+23]
    in1v2w = parse_input(in1v2w)
    
    print_result(in0*in1v2w) # mul by v^2w

    # prepare in1v2nrinv
    temp = fp2([sys.argv[i+16], sys.argv[i+17]])
    temp *= binv
    temp = field_to_list(temp)
    in1v2nrinv = ["0"]*12
    in1v2nrinv[4]=str(temp[0])
    in1v2nrinv[5]=str(temp[1])
    in1v2nrinv = parse_input(in1v2nrinv)

    print_result(in0*in1v2nrinv) # mul by v^2 * non-residue inverse

    # prepare in1vwnrinv
    temp = fp2([sys.argv[i+20], sys.argv[i+21]])
    temp *= binv
    temp = field_to_list(temp)
    in1vwnrinv = ["0"]*12
    in1vwnrinv[8]=str(temp[0])
    in1vwnrinv[9]=str(temp[1])
    in1vwnrinv = parse_input(in1vwnrinv)
    
    print_result(in0*in1vwnrinv) # mul by vw * non-residue inverse

    # prepare in1wnrinv
    temp = fp2([sys.argv[i+18], sys.argv[i+19]])
    temp *= binv
    temp = field_to_list(temp)
    in1wnrinv = ["0"]*12
    in1wnrinv[6]=str(temp[0])
    in1wnrinv[7]=str(temp[1])
    in1wnrinv = parse_input(in1wnrinv)
    
    print_result(in0*in1wnrinv) # mul by w * non-residue inverse

    # unary ops ignore in1
    print_result(in0*in0) # square

    # inv
    if in0==fp12.zero():
        print_result(fp12.zero()) # can't invert 0; just output 0
    else:
        print_result(in0^(-1))
    
    print_result(in0.conjugate()) # conjugate
    print_result(fp12.frobenius_endomorphism()(in0)) # frobenius
    print_result(fp12.frobenius_endomorphism(2)(in0)) # frobenius squared
    print_result(fp12.frobenius_endomorphism(3)(in0)) # frobenius cubed
    print_result(in0^t) # expt
    print_result(in0^exponent) # final exponent
