import io as _; import sys, os
sys.path.insert(0,os.path.dirname(os.path.abspath(__file__)))
import importlib.util
spec=importlib.util.spec_from_file_location("mio", os.path.join(os.path.dirname(os.path.abspath(__file__)), "io.py")); mio=importlib.util.module_from_spec(spec); spec.loader.exec_module(mio)
t=mio.start()
for i in list(range(1020,1040))+list(range(1540,1552)):
    try: v=mio.read(t,i)
    except EOFError as e: print(i,"DEAD"); break
    print("mem[%4d] = 0x%016x"%(i,v))
t.close()
