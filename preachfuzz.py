#!/usr/bin/env python
# coding: utf-8
import angr
import claripy
import time
import os

import config
from llvm_instr import GDBExecutor
branch_instrs = ["ja","jae","jb","jbe","jc","je","jecxz","jg","jge","jl","jle","jna","jnae","jnb","jnbe","jnc","jne","jng",
              "jnge","jnl","jnle","jno","jnp","jns","jnz","jo","jp","jpe","jpo","js","jz"]
cmp_instrs = ["cmp", "test","FUCOM","FUCOMP","FUCOMPP","FUCOMI","FUCOMIP","FTST","FXAM","FCOM","FCOMP","FCOMPP","FICOM","FICOMP","FCOMI","FCOMIP"]

floc = f"/tmp/objdump-log-{time.time()}"
os.system(f"objdump -d {config.LOCAL_UNINSTRUMENTED_EXEC_PATH} > {floc}")

mapping = {}

gdb = GDBExecutor(config.LOCAL_UNINSTRUMENTED_EXEC_PATH)
hardest_path = [f"test.c:{x}:-1".encode("ascii") for x in [13, 19, 23, 26, 27, 30, 31, 34, 35, 38, 39, 42, 43, 46, 47]]

solve_for_addr = []

for i in hardest_path:
    addrs = gdb.get_addr(i)
    solve_for_addr.append(addrs[0])
    solve_for_addr.append(addrs[1])

print(solve_for_addr)
# for line in open(floc).read().split("\n"):
#     line_arr = line.split("\t")
#     if len(line_arr) > 2 and ("nop" in line_arr[-1]):
#         continue
#     if record_next or driver_part:
#         if len(line_arr) > 1:
#             pc = int("0x" + line_arr[0].split(":")[0].replace(" ", ""), 16)
#             self.__non_comp_bb.add(pc)
#         record_next = False
#
#     # todo: parse instead of direct match
#     if len(line_arr) > 2 and ("call" in line_arr[-1] or "jmp" in line_arr[-1]):
#         record_next = True
#     if len(line_arr) == 1:
#         record_next = True
#         driver_part = False
#     if len(line_arr) == 1 and ("<main>" in line_arr[-1] or "<__libc_csu" in line_arr[-1]):
#         driver_part = True


p = angr.Project('harness')


state = p.factory.full_init_state(
        args=['./harness', 'v'],

        add_options=angr.options.unicorn,
        stdin=angr.SimFile,
)
state.options.add(angr.options.LAZY_SOLVES)

while True:
    succ = state.step()
    if len(succ.successors) == 2:
        break
    state = succ.successors[0]


print(state)
