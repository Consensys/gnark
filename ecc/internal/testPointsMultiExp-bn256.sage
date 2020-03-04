#!/usr/bin/env sage

import sys
from sage.all import *

# Compute the result of a multi-exponentiation in the G1, G2 torsion groups of bn256

# set numPoints as desired
numPoints=10000

# bn256 fp modulus
p=21888242871839275222246405745257275088696311157297823662689037894645226208583

# bn256 fr modulus
r=21888242871839275222246405745257275088548364400416034343698204186575808495617

# large multiplicative generator of fr
exp=18147194858733678592031140175294542593979808267792252765512745512101703194607

#
# G1
#
Fp=GF(p)
E=EllipticCurve(Fp, [0,3])

# generator of torsion group G1 with order r
G1=E(20567171726433170376993012834626974355708098753738075953327671604980729474588,14259118686601658563517637559143782061303537174604067025175876803301021346267)

R1=G1-G1 # initialize point at infinity
nextpoint=R1
nextscalar=1
for i in range(numPoints):
    nextpoint = nextpoint + G1
    nextscalar = nextscalar * exp % r
    R1 = R1 + nextscalar * nextpoint
print "G1:", numPoints, R1

#
# G2
#
Fp2.<u> = GF(p^2, modulus=x^2+1)
Etwist = EllipticCurve(Fp2, [0, 3*(u+9)^-1])

# generator of torsion group G2 with order r
G2 = Etwist([14433365730775072582213482468844163390964025019096075555058505630999708262443+3683446723006852480794963570030936618743148392137679437247363531986401769417*u, 21253271987667943455369004300257637004831224612428754877033343975009216128128+12495620673937637012904672587588023149812491484245871073230980321212840773339*u])

R2=G2-G2 # initialize point at infinity
nextpoint=R2
nextscalar=1
for i in range(numPoints):
    nextpoint = nextpoint + G2
    nextscalar = nextscalar * exp % r
    R2 = R2 + nextscalar * nextpoint
print "G2:", numPoints, R2
