import random,sys,os
sys.path.insert(0,os.path.dirname(os.path.abspath(__file__)))
import model
VARS="abcdefgh"
def gen(d=0):
    r=random.random()
    if d>3 or r<0.4:
        c=random.random()
        if c<0.18: return "_load(%s)"%random.choice(VARS)
        if c<0.30: return "_store(%s, %s)"%(random.choice(VARS),random.choice(VARS))
        return random.choice(VARS)
    if r<0.72: return "(%s %s %s)"%(gen(d+1),random.choice("+-*"),gen(d+1))
    if r<0.84: return "_store(%s, %s)"%(random.choice(VARS),gen(d+1))
    if r<0.92: return "_max(%s, %s)"%(gen(d+1),gen(d+1))
    return "_load(%s)"%gen(d+1)
def isvar(s): return isinstance(s,tuple) and s[0]=='var'
def contains(sym,v):
    if not isinstance(sym,tuple): return False
    if sym[0]=='var': return sym[1]==v
    return any(contains(x,v) for x in sym[1:])
random.seed(int(sys.argv[1])); best=[]
for i in range(600000):
    F=gen()
    if len(F)>120: continue
    p=random.choice(VARS); q=random.choice(VARS); s=random.choice(VARS)
    e="((%s) * 0) + _load(%s) + (_store(%s, %s) * 0)"%(F,p,q,s)
    try: ssa,res,ir,ev=model.analyze(e)
    except Exception: continue
    acc=[x for x in ev if x[0] in ('load','store')]
    loads=[x for x in acc if x[0]=='load']; stores=[x for x in acc if x[0]=='store']
    if not loads or not stores: continue
    RL, WS = loads[-1], stores[-1]
    if RL[2] is not False or not isvar(RL[1]): continue
    if WS[2] is not False or not isvar(WS[1]) or not isvar(WS[3]): continue
    X, V = RL[1][1], WS[3][1]
    if WS[1][1]!=X: continue
    if X==V: continue
    ok=True
    for x in acc:
        if x is RL or x is WS: continue
        if contains(x[1],X) or contains(x[1],V): ok=False;break
    if not ok: continue
    print("LEN%3d idx=%s val=%s :: %s"%(len(e),X,V,e)); best.append((len(e),e,X,V))
    if len(best)>=8: break
best.sort()
print("\nSHORTEST:",best[0] if best else None)
