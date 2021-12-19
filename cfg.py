import sys
from functools import reduce

import angr
import claripy



def get_result_solver(s, e, **kwargs):
    s.reload_solver()
    cast_vals = [s._cast_to(e, v, bytes) for v in s._eval(e, 1, **kwargs)]
    return cast_vals


def main(exe, arg):
    prog = Program(exe)
    prog.set_input(arg)
    res = prog.run()
    print(res.solver.constraints)
    i = 0
    prog.pop_added_cons(res)
    print("constraints: %d" % len(res.solver.constraints))
    print(res.solver.constraints)
    print(get_result_solver(res.solver, prog.arg1))
    print('done')



if __name__ == '__main__':
    # assert len(sys.argv) >= 3
    main("test.angr", "fuckfff")
