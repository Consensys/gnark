# big numbers
charac = 258664426012969094010652733694893533536393512754914660539884262666720468348340822774968888139573360124440321458177
r = 8444461749428370424248824938781546531375899335154063827935233455917409239041
k = 12

# field definition
F.<w> = GF(charac**12, modulus = x**12 - 5)

# twist param w
twist = w**-1

# curves definition
E = EllipticCurve(F, [0,1])
Etwist = EllipticCurve(F, [0,twist**6])

def frobenius(P):
    '''
    Computes the f(P)

    # input
        P affine point

    # output
        (Px**q,Py**q, 1)
    '''
    Px = P[0]**charac
    Py = P[1]**charac

    R = [Px, Py, F(1)]
    return E(R)

def trace(P):
    '''
    Computes the trace of P

    # input
        P affine point

    # output
        trace of P
    '''
    _P = P
    R = P
    for i in range(1,k):
        _P = frobenius(_P)
        R += _P

    return R

def anti_trace(P):
    '''
    computes the anti trace of P (maps P on ker(pi - [q])

    # input
        P affine point

    # output
        anti trace map on [q]P - trace(P)
    '''
    Q = k*P - trace(P)
    return Q

def generate_point_G2():
    '''
    generates a point on G2

    # output
        an affine point on G2 = ker(pi - [q])
    '''
    P = E.random_element()
    P = Integer(E.cardinality()/(r**2))*P
    P = anti_trace(P)
    return P

def psi(P):
    '''
    computes the image of P on the twist

    # input
        P affine point on E

    # output
        psi(P) affine point on Etwist
    '''
    Px = P[0] * twist**2
    Py = P[1] * twist**3
    Pz = P[2]
    return Etwist([Px, Py, Pz])

def psiinv(P):
    '''
    computes the map E' -> E

    # input
        P affine point on Etwist

    # output
        psi-1(P) affine point on E
    '''
    Px = P[0]* twist**-2
    Py = P[1]* twist**-3
    Pz = P[2]
    return E([Px, Py, Pz])

def lineEval(Q, R, P):
    '''
    Evals the line function through Q and R at P
    Q must be different from P
    The case tangent at infinity point is not handled

    # input
        Q, R: points on Element12 (affine)
        P: point on Element (affine : (X/Z, Y/Z)
    
    # output
        evaluation of the line through Q and R at P
    '''
    matx = matrix([[Q[1],Q[2]],[R[1],R[2]]])
    maty = matrix([[Q[0],Q[2]],[R[0],R[2]]])
    matz = matrix([[Q[0],Q[1]],[R[0],R[1]]])
    a = matx.determinant()
    b = maty.determinant()
    c = matz.determinant()
    res = -(P[0]*a - P[1]*b + P[2]*c)
    print("line eq: y + ({0})*x + {1}".format(-a/b, -c/b))
    return res

def tanEval(Q, P):
    '''
    Evals the tangent at Q at P
    in the affine chart z/=0

    # input
        Q: point on Element12 (affine)
        P: point on Element (affine)

    # output
        evaluation of the tangent at Q at P
    '''
    a = -3*Q[0]**2
    b = 2*Q[1]
    c = -2*Q[1]**2 + 3*Q[0]**3
    res = (a*P[0]+b*P[1]+c)/b
    print("line eq: y + ({0})*x + {1}".format(a/b, c/b))

def toAffine(x, y, z):
    '''
    converts from Jacobian to affine
    '''
    x = x/(z**2)
    y = y/(z**3)
    z = 1
    return [x, y, z]