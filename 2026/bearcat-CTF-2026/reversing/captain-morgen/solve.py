import ast, pycosat
from functools import lru_cache

src = open('chall.py').read()
mod = ast.parse(src)
assigns = []

def desugar(n):
    if isinstance(n, ast.NamedExpr):
        v = desugar(n.value)
        assigns.append((n.target.id, v))
        return ast.Name(id=n.target.id, ctx=ast.Load())
    if isinstance(n, ast.BinOp):
        return ast.BinOp(left=desugar(n.left), op=n.op, right=desugar(n.right))
    if isinstance(n, ast.UnaryOp):
        return ast.UnaryOp(op=n.op, operand=desugar(n.operand))
    if isinstance(n, ast.BoolOp):
        return ast.BoolOp(op=n.op, values=[desugar(x) for x in n.values])
    if isinstance(n, ast.IfExp):
        return ast.IfExp(test=desugar(n.test), body=desugar(n.body), orelse=desugar(n.orelse))
    if isinstance(n, ast.Compare):
        return ast.Compare(left=desugar(n.left), ops=n.ops, comparators=[desugar(c) for c in n.comparators])
    if isinstance(n, ast.Call):
        return ast.Call(func=desugar(n.func), args=[desugar(a) for a in n.args], keywords=[ast.keyword(arg=k.arg, value=desugar(k.value)) for k in n.keywords])
    if isinstance(n, ast.Attribute):
        return ast.Attribute(value=desugar(n.value), attr=n.attr, ctx=n.ctx)
    if isinstance(n, ast.Subscript):
        return ast.Subscript(value=desugar(n.value), slice=desugar(n.slice), ctx=n.ctx)
    if isinstance(n, ast.Slice):
        return ast.Slice(lower=desugar(n.lower) if n.lower else None, upper=desugar(n.upper) if n.upper else None, step=desugar(n.step) if n.step else None)
    if isinstance(n, ast.Tuple):
        return ast.Tuple(elts=[desugar(e) for e in n.elts], ctx=n.ctx)
    return n

for st in mod.body:
    if isinstance(st, ast.Assign) and len(st.targets) == 1 and isinstance(st.targets[0], ast.Name):
        assigns.append((st.targets[0].id, desugar(st.value)))

exprs = {k: v for k, v in assigns}

next_var = 1
clauses = []

def new_var():
    global next_var
    v = next_var
    next_var += 1
    return v

T = new_var(); clauses.append([T])
TRUE, FALSE = T, -T

ari_bits = {}
def ari(i):
    if i < 0:
        return FALSE
    if i not in ari_bits:
        ari_bits[i] = new_var()
    return ari_bits[i]

def is_t(x): return x == TRUE
def is_f(x): return x == FALSE
cache_gate = {}

def g_and(a,b):
    if is_f(a) or is_f(b): return FALSE
    if is_t(a): return b
    if is_t(b): return a
    if a == b: return a
    if a == -b: return FALSE
    key = ('a',a,b) if a <= b else ('a',b,a)
    if key in cache_gate: return cache_gate[key]
    c = new_var(); clauses.extend([[-c,a],[-c,b],[c,-a,-b]]); cache_gate[key] = c; return c

def g_or(a,b):
    if is_t(a) or is_t(b): return TRUE
    if is_f(a): return b
    if is_f(b): return a
    if a == b: return a
    if a == -b: return TRUE
    key = ('o',a,b) if a <= b else ('o',b,a)
    if key in cache_gate: return cache_gate[key]
    c = new_var(); clauses.extend([[c,-a],[c,-b],[-c,a,b]]); cache_gate[key] = c; return c

def g_xor(a,b):
    if is_f(a): return b
    if is_f(b): return a
    if is_t(a): return -b
    if is_t(b): return -a
    if a == b: return FALSE
    if a == -b: return TRUE
    key = ('x',a,b) if a <= b else ('x',b,a)
    if key in cache_gate: return cache_gate[key]
    c = new_var(); clauses.extend([[-a,-b,-c],[-a,b,c],[a,-b,c],[a,b,-c]]); cache_gate[key] = c; return c

BASE = {'bhy': 1, 'aja': 1}
def cbit(v,i):
    if i < 0: return FALSE
    return TRUE if ((v >> i) & 1) else FALSE

@lru_cache(maxsize=None)
def const_eval(expr_src):
    n = ast.parse(expr_src, mode='eval').body
    def go(x):
        if isinstance(x, ast.Constant) and isinstance(x.value, (int,bool)): return int(x.value)
        if isinstance(x, ast.Name) and x.id in BASE: return BASE[x.id]
        if isinstance(x, ast.BinOp):
            a,b = go(x.left), go(x.right)
            if isinstance(x.op, ast.BitAnd): return a & b
            if isinstance(x.op, ast.BitOr): return a | b
            if isinstance(x.op, ast.BitXor): return a ^ b
            if isinstance(x.op, ast.RShift): return a >> b
            if isinstance(x.op, ast.LShift): return a << b
        raise ValueError
    return go(n)

vcache, ecache = {}, {}
def vbit(name,i):
    k = (name,i)
    if k in vcache: return vcache[k]
    if name in BASE: lit = cbit(BASE[name], i)
    elif name == 'ari': lit = ari(i)
    else: lit = ebit(exprs[name], i)
    vcache[k] = lit
    return lit

def ebit(node,i):
    k = (id(node), i)
    if k in ecache: return ecache[k]
    if isinstance(node, ast.Constant) and isinstance(node.value,(int,bool)):
        lit = cbit(int(node.value), i)
    elif isinstance(node, ast.Name):
        lit = vbit(node.id, i)
    elif isinstance(node, ast.BinOp):
        if isinstance(node.op, ast.RShift):
            sh = const_eval(ast.unparse(node.right))
            lit = ebit(node.left, i + sh)
        elif isinstance(node.op, ast.BitAnd):
            lit = g_and(ebit(node.left, i), ebit(node.right, i))
        elif isinstance(node.op, ast.BitOr):
            lit = g_or(ebit(node.left, i), ebit(node.right, i))
        elif isinstance(node.op, ast.BitXor):
            lit = g_xor(ebit(node.left, i), ebit(node.right, i))
        else:
            raise NotImplementedError
    else:
        raise NotImplementedError
    ecache[k] = lit
    return lit

clauses.append([-vbit('bfu', 0)])  # require output == "correct"
sol = pycosat.solve(clauses)
if isinstance(sol, str):
    raise SystemExit(sol)
M = {x for x in sol if x > 0}
ari_val = 0
for i, v in ari_bits.items():
    if v in M:
        ari_val |= (1 << i)

inner = ari_val.to_bytes((ari_val.bit_length() + 7)//8, 'big').decode()
print(f'BCCTF{{{inner}}}')
