import argparse
import sys

from sage.all import *


parser = argparse.ArgumentParser("Test point generator")

parser.add_argument('-p', action='store', dest='modulus', help='modulus', type=str, required=True)
parser.add_argument('-b', action='store', dest='nonsquare', help='non square element', type=str, required=True)
parser.add_argument('-op', action='store', dest='cmd', help='operation (add, sub, mul or inv)', type=str, required=True)
parser.add_argument('--points', nargs='+')

# p=sage_eval(sys.argv[1]) # prime characteristic p
# b=sage_eval(sys.argv[2]) # x^2-b must be irrep modulo p
# Fp2.<u> = GF(p^2, modulus=x^2-b)

def result(in1, in2, cmd):
    '''
    combines in1, in2 according to cmd
    '''
    if cmd == "add":
        return in1+in2
    elif cmd == "sub":
        return in1-in2
    elif cmd == "mul":
        return in1*in2
    else:
        print("option '%s' not supported" % sys.argv[3])
        sys.exit(1)

if __name__ == "__main__":
    
    results = parser.parse_args()

    for _, value in results._get_kwargs():
        print(value)
    #print results.ps

    # for i in range(4, len(sys.argv), 4):
   
    #     in1=Fp2(sage_eval(sys.argv[i]) + sage_eval(sys.argv[i+1])*u)
    #     in2=Fp2(sage_eval(sys.argv[i+2]) + sage_eval(sys.argv[i+3])*u)
    #     out = result(in1, in2, sys.argv[3])

    #     # python truncates leading 0s
    #     outlist = out.polynomial().list()
    #     while len(outlist) < 2:
    #         outlist.append(0)
        
    #     print outlist[0]
    #     print outlist[1]
