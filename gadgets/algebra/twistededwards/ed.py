class point:
    def __init__(self, x, y):
        self.x = x
        self.y = y
 
class edCurve:
    def __init__(self, a, d, base):
        self.a = a
        self.d = d
        self.base = base

    def add(self, p1, p2):
        res = point(Fr(0), Fr(0))
        res.x = (p1.x*p2.y+p1.y*p2.x)*(Fr(1)+self.d*p1.x*p2.x*p1.y*p2.y)**-1
        res.y = (p1.y*p2.y - self.a*p1.x*p2.x)*(Fr(1)-self.d*p1.x*p2.x*p1.y*p2.y)**-1
        return res
     
    def neg(self, p1):
        res = point(0,0)
        res.x = -p1.x
        res.y = p1.y
        return res

    def isOnCurve(self, p1):
        l = self.a*p1.x**2+p1.y**2
        r = Fr(1) + self.d*p1.x**2*p1.y**2
        return l==r
