import random, subprocess, os, re, sys
sys.path.insert(0,os.path.dirname(os.path.abspath(__file__)))
import model
BIN="/home/null/Desktop/vuwCTF-2026/pwn/moose-calc/moosecalc"; CWD=os.path.dirname(BIN)
NAME="ABCD"
OPCH={'ADD':'+','SUB':'-','MUL':'*','DIV':'/','POW':'^'}
def render(ir,rr,mx):
    o=[]
    for i in ir:
        t=i.type
        if t=='LOAD_LITERAL': o.append("  %c = load %g"%(NAME[i.dest],i.val))
        elif t=='LOAD_INPUT': o.append("  %c = load_input %c"%(NAME[i.dest],i.var))
        elif t=='BINARY': o.append("  %c = %c %c %c"%(NAME[i.dest],NAME[i.left],OPCH[i.op],NAME[i.right]))
        elif t=='NEGATE': o.append("  %c = neg %c"%(NAME[i.dest],NAME[i.src]))
        elif t=='UN_INTRIN': o.append("  %c = %s %c"%(NAME[i.dest],i.fn,NAME[i.src]))
        elif t=='BIN_INTRIN': o.append("  %c = %s %c %c"%(NAME[i.dest],i.fn,NAME[i.left],NAME[i.right]))
        elif t=='CHECK_BOUNDS': o.append("  check_bounds %c"%NAME[i.reg])
        elif t=='SPILL': o.append("  spill %c -> [%d]"%(NAME[i.reg],i.slot))
        elif t=='RESTORE': o.append("  restore [%d] -> %c"%(i.slot,NAME[i.reg]))
    o.append("  result: %c"%NAME[rr]); o.append("  (stack slots used: %d)"%mx)
    return "\n".join(o)
def real(expr):
    p=subprocess.run([BIN],input=expr+"\na\n\n",capture_output=True,text=True,
                     env={**os.environ,"JIT_DEBUG":"1"},cwd=CWD,timeout=10)
    m=re.search(r"result: r\d+\n\n(.*?stack slots used: \d+\))",p.stdout,re.S)
    return m.group(1) if m else None
VARS="abcdefghij"
def gen(d=0):
    r=random.random()
    if d>3 or r<0.35:
        c=random.random()
        if c<0.2: return "_load(%s)"%random.choice(VARS)
        if c<0.25: return str(random.randint(0,9))
        return random.choice(VARS)
    if r<0.7: return "(%s %s %s)"%(gen(d+1),random.choice("+-*/"),gen(d+1))
    if r<0.8: return "_store(%s, %s)"%(random.choice(VARS),gen(d+1))
    if r<0.9: return "_max(%s, %s)"%(gen(d+1),gen(d+1))
    return "_load(%s)"%gen(d+1)
random.seed(99); bad=0; n=0
for i in range(500):
    e=gen()
    if len(e)>250: continue
    try: ssa,res,ir,ev=model.analyze(e)
    except Exception as ex: continue
    toks=model.tokenize(e); s2,r2=model.parse(toks); ir2,rr,mx=model.generate_ir(s2,r2)
    mine=render(ir2,rr,mx); r=real(e)
    if r is None: continue
    n+=1
    if mine.strip()!=r.strip():
        bad+=1
        if bad==1: print("MISMATCH on",e); print("--mine--"); print(mine); print("--real--"); print(r)
print("compared %d, mismatches %d"%(n,bad))
