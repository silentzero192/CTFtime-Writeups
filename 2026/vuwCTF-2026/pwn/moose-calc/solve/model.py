"""Faithful port of moosecalc.c tokenize/parse/generate_ir + symbolic IR simulation."""
MAX_DEPTH=64; MAX_SSA=256; NUM_REGS=4

OPS={'+':'ADD','-':'SUB','*':'MUL','/':'DIV','^':'POW'}
UN={'_sin':'sin','_cos':'cos','_exp':'exp','_log':'log','_sqrt':'sqrt','_load':'load'}
BIN={'_max':'max','_min':'min','_pow':'pow','_store':'store'}
MAPPINGS=[(k,('OP',v)) for k,v in OPS.items()]+ \
         [(k,('UN',v)) for k,v in [('_sin','sin'),('_cos','cos'),('_exp','exp'),('_log','log'),('_sqrt','sqrt'),('_load','load')]]+ \
         [(k,('BIN',v)) for k,v in [('_max','max'),('_min','min'),('_pow','pow'),('_store','store')]]+ \
         [(',',('COMMA',None)),('(',('LPAREN',None)),(')',('RPAREN',None))]

def tokenize(s):
    toks=[]; i=0
    while i<len(s) and s[i]!='\n':
        if s[i] in ' \t\r\v\f': i+=1; continue
        m=None
        for name,tk in MAPPINGS:
            if not s.startswith(name,i): continue
            if tk[0] in ('UN','BIN'):
                nxt=s[i+len(name)] if i+len(name)<len(s) else '\0'
                if nxt.isdigit() or ('a'<=nxt<='z') or nxt=='_': continue
            m=(name,tk); break
        if m: toks.append(m[1]); i+=len(m[0]); continue
        if s[i].isdigit():
            j=i
            while j<len(s) and (s[j].isdigit() or s[j]=='.'): j+=1
            toks.append(('NUM',float(s[i:j]))); i=j; continue
        if 'a'<=s[i]<='z': toks.append(('VAR',s[i])); i+=1; continue
        raise ValueError("bad char %r"%s[i])
    toks.append(('END',None))
    return toks

class Ssa:
    def __init__(s,t,**kw): s.type=t; s.__dict__.update(kw)
    def __repr__(s): return "%s%s"%(s.type,{k:v for k,v in s.__dict__.items() if k!='type'})

def parse(toks):
    ssa=[]
    def emit(i): i.dest=len(ssa); ssa.append(i); return i.dest
    reg_stack=[0]*MAX_DEPTH; pending_op=[None]*MAX_DEPTH; has_pending=[0]*MAX_DEPTH
    intrin_names=[None]*MAX_DEPTH; intrin_at=[0]*MAX_DEPTH
    bin_names=[None]*MAX_DEPTH; bin_at=[0]*MAX_DEPTH; bin_arg1=[0]*MAX_DEPTH; bin_comma=[0]*MAX_DEPTH
    cache={}; depth=0; pos=0; nunary=0; reg=None
    state='primary'
    while True:
        if state=='primary':
            while toks[pos][0]=='OP' and toks[pos][1] in ('SUB','ADD'):
                if toks[pos][1]=='SUB': nunary+=1
                pos+=1
            t=toks[pos]
            if t[0]=='NUM':
                reg=emit(Ssa('LOAD_LITERAL',literal=t[1])); pos+=1; state='have_atom'
            elif t[0]=='VAR':
                if t[1] in cache: reg=cache[t[1]]
                else: reg=cache[t[1]]=emit(Ssa('LOAD_VAR',var=t[1]))
                pos+=1; state='have_atom'
            elif t[0]=='UN':
                intrin_names[depth+1]=t[1]; intrin_at[depth+1]=1; bin_at[depth+1]=0
                pos+=1; assert toks[pos][0]=='LPAREN'; pos+=1; depth+=1; has_pending[depth]=0
            elif t[0]=='BIN':
                bin_names[depth+1]=t[1]; bin_at[depth+1]=1; bin_comma[depth+1]=0; intrin_at[depth+1]=0
                pos+=1; assert toks[pos][0]=='LPAREN'; pos+=1; depth+=1; has_pending[depth]=0
            elif t[0]=='LPAREN':
                pos+=1; depth+=1; has_pending[depth]=0; intrin_at[depth]=0; bin_at[depth]=0
            else: raise ValueError("expected expression at %d"%pos)
            continue
        # have_atom
        while nunary>0:
            reg=emit(Ssa('UNARY_NEGATIVE',src=reg)); nunary-=1
        if has_pending[depth]:
            reg=emit(Ssa('BINARY_OP',op=pending_op[depth],left=reg_stack[depth],right=reg))
            has_pending[depth]=0
        reg_stack[depth]=reg
        t=toks[pos]
        if t[0]=='OP':
            pending_op[depth]=t[1]; has_pending[depth]=1; pos+=1; state='primary'; continue
        if t[0]=='COMMA':
            assert bin_at[depth] and not bin_comma[depth], "unexpected ,"
            bin_arg1[depth]=reg_stack[depth]; bin_comma[depth]=1; has_pending[depth]=0
            pos+=1; state='primary'; continue
        if t[0]=='RPAREN':
            assert depth>0
            reg=reg_stack[depth]
            if intrin_at[depth]:
                reg=emit(Ssa('UN_INTRIN',intrin=intrin_names[depth],src=reg)); intrin_at[depth]=0
            elif bin_at[depth]:
                assert bin_comma[depth], "bin intrinsic needs 2 args"
                reg=emit(Ssa('BIN_INTRIN',fn=bin_names[depth],left=bin_arg1[depth],right=reg)); bin_at[depth]=0
            depth-=1; pos+=1; state='have_atom'; continue
        if t[0]=='END':
            assert depth==0, "unclosed paren"
            return ssa, reg_stack[0]
        raise ValueError("unexpected token")

class Ir:
    def __init__(s,t,**kw): s.type=t; s.__dict__.update(kw)
    def __repr__(s): return "%s%s"%(s.type,{k:v for k,v in s.__dict__.items() if k!='type'})

def generate_ir(ssa, result):
    nssa=len(ssa)
    last_use=list(range(nssa))
    for i,ins in enumerate(ssa):
        if ins.type=='BINARY_OP': last_use[ins.left]=i; last_use[ins.right]=i
        elif ins.type=='UNARY_NEGATIVE': last_use[ins.src]=i
        elif ins.type=='UN_INTRIN': last_use[ins.src]=i
        elif ins.type=='BIN_INTRIN': last_use[ins.left]=i; last_use[ins.right]=i
    last_use[result]=nssa
    ir=[]
    var_state=[0]*MAX_SSA   # 0 UNINIT 1 REG 2 SPILLED 3 DROPPED
    var_reg=[0]*MAX_SSA; var_slot=[0]*MAX_SSA
    reg_owner=[-1]*NUM_REGS; in_use=[0]*NUM_REGS
    checked=[0]*MAX_SSA
    st={'n':0,'max':0}
    def alloc_reg(sr):
        victim=-1
        for r in range(NUM_REGS):
            if reg_owner[r]<0:
                reg_owner[r]=sr; var_state[sr]=1; var_reg[sr]=r; in_use[r]=1; return r
            if in_use[r]: continue
            if victim<0 or last_use[reg_owner[r]]>last_use[reg_owner[victim]]: victim=r
        if victim<0 or in_use[victim]: raise RuntimeError("all pinned")
        ir.append(Ir('SPILL',reg=victim,slot=st['n']))
        var_state[reg_owner[victim]]=2; var_slot[reg_owner[victim]]=st['n']
        st['n']+=1; st['max']=max(st['max'],st['n'])
        reg_owner[victim]=sr; var_state[sr]=1; var_reg[sr]=victim; in_use[victim]=1
        return victim
    def ensure_reg(sr):
        if var_state[sr]==1: return var_reg[sr]
        slot=var_slot[sr]
        r=alloc_reg(sr)
        ir.append(Ir('RESTORE',reg=r,slot=slot))
        st['n']-=1
        return r
    def drop(sr,r,i):
        if last_use[sr]==i: reg_owner[r]=-1; var_state[sr]=3
    for i,ins in enumerate(ssa):
        for r in range(NUM_REGS): in_use[r]=0
        if ins.type=='LOAD_LITERAL':
            d=alloc_reg(i); ir.append(Ir('LOAD_LITERAL',dest=d,val=ins.literal,ssa=i))
        elif ins.type=='LOAD_VAR':
            d=alloc_reg(i); ir.append(Ir('LOAD_INPUT',dest=d,var=ins.var,ssa=i))
        elif ins.type=='UNARY_NEGATIVE':
            s=ensure_reg(ins.src); drop(ins.src,s,i); d=alloc_reg(i)
            ir.append(Ir('NEGATE',dest=d,src=s,ssa=i))
        elif ins.type=='UN_INTRIN':
            s=ensure_reg(ins.src)
            if ins.intrin=='load' and not checked[ins.src]:
                ir.append(Ir('CHECK_BOUNDS',reg=s,ssa=i,for_ssa=ins.src)); checked[ins.src]=1
            drop(ins.src,s,i); d=alloc_reg(i)
            ir.append(Ir('UN_INTRIN',dest=d,src=s,fn=ins.intrin,ssa=i))
        elif ins.type=='BIN_INTRIN':
            l=ensure_reg(ins.left); r=ensure_reg(ins.right)
            if ins.fn=='store' and not checked[ins.left]:
                ir.append(Ir('CHECK_BOUNDS',reg=l,ssa=i,for_ssa=ins.left)); checked[ins.left]=1
            drop(ins.left,l,i); drop(ins.right,r,i); d=alloc_reg(i)
            ir.append(Ir('BIN_INTRIN',dest=d,left=l,right=r,fn=ins.fn,ssa=i))
        elif ins.type=='BINARY_OP':
            l=ensure_reg(ins.left); r=ensure_reg(ins.right)
            drop(ins.left,l,i); drop(ins.right,r,i); d=alloc_reg(i)
            if ins.op=='POW': ir.append(Ir('BIN_INTRIN',dest=d,left=l,right=r,fn='pow',ssa=i))
            else: ir.append(Ir('BINARY',dest=d,left=l,right=r,op=ins.op,ssa=i))
    for r in range(NUM_REGS): in_use[r]=0
    rr=ensure_reg(result)
    return ir, rr, st['max']

def simulate(ir, ssa):
    """Symbolically execute the IR: regs/slots hold SSA ids. Return list of
    (kind, index_symbol, checked_symbols_so_far) for every load/store."""
    reg=[None]*NUM_REGS; slot={}
    checked=set(); events=[]
    for ins in ir:
        t=ins.type
        if t=='SPILL': slot[ins.slot]=reg[ins.reg]
        elif t=='RESTORE': reg[ins.reg]=slot.get(ins.slot)
        elif t=='LOAD_LITERAL': reg[ins.dest]=('lit',ins.val)
        elif t=='LOAD_INPUT': reg[ins.dest]=('var',ins.var)
        elif t=='NEGATE': reg[ins.dest]=('neg',reg[ins.src])
        elif t=='CHECK_BOUNDS': checked.add(id_of(reg[ins.reg])); events.append(('check',reg[ins.reg],None))
        elif t=='UN_INTRIN':
            if ins.fn=='load':
                events.append(('load',reg[ins.src],id_of(reg[ins.src]) in checked))
            reg[ins.dest]=(ins.fn,reg[ins.src])
        elif t=='BIN_INTRIN':
            if ins.fn=='store':
                events.append(('store',reg[ins.left],id_of(reg[ins.left]) in checked,reg[ins.right]))
            reg[ins.dest]=(ins.fn,reg[ins.left],reg[ins.right])
        elif t=='BINARY': reg[ins.dest]=(ins.op,reg[ins.left],reg[ins.right])
    return events

def id_of(sym): return repr(sym)

def analyze(expr):
    toks=tokenize(expr); ssa,res=parse(toks); ir,rr,mx=generate_ir(ssa,res)
    return ssa,res,ir,simulate(ir,ssa)
