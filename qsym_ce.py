import config
import z3


# hacky smt parsing
def remove_assert(string):
    cter = -1
    met_assert = False
    while 1:
        cter += 1
        if met_assert and string[cter] == 40:
            string = string[cter:]
            break
        if string[cter] == 40:  # b'('
            met_assert = True
            continue
    cter = len(string)
    while 1:
        cter -= 1
        if string[cter] == 41:  # b')'
            string = string[:cter]
            break
    return string


def negate_smt2(string):
    string = remove_assert(string)
    return f'(assert (not {string.decode("utf-8")}))'.encode('utf-8')


def solve_smt(smt):
    s = z3.Solver()
    s.from_string(smt)
    try:
        s.check()

        m = s.model()
        result = []
        for d in m.decls():
            result.append([d.name(), m[d]])
        result = sorted(result, key=lambda x: x[0])
        return bytes([int(x[1].__str__()) for x in result])
    except Exception as e:
        print(f"[Solver] UNSAT {e}")


def to_smt2(bvs, constraints):
    smt2 = b''
    for bv in bvs:
        smt2 += bv + b'\n'
    smt2 += constraints + b'\n'
    return smt2.decode('utf-8')


class QSYMConcolicExecutor:
    def __init__(self, uninstrumented_executable):
        self.uninstrumented_executable = uninstrumented_executable
        self.cmp_constraint = {}
        self.execution_tree = None

    def update_exec_tree(self, tree):
        self.execution_tree = tree

    def __run_qsym_remote(self, corpus_content):
        config.QSYM_SSH_CONN.process(["mkdir", "in"])
        config.QSYM_SSH_CONN.process(["mkdir", "out"])
        qsym_instance = config.QSYM_SSH_CONN.process([config.PIN_SH, '-ifeellucky', '-t',
                                               config.QSYM_OBJECT_PATH, '-i', 'in', '-o', 'out', '--',
                                               self.uninstrumented_executable, str(len(corpus_content) + 1)])
        qsym_instance.sendline(corpus_content)
        result = qsym_instance.recvall(timeout=config.QSYM_TIMEOUT)
        return result

    @staticmethod
    def __parse_output_flipme(lines: [bytes]):
        recording = False
        current_pc = -1
        current_constraint = b''
        cmp_constraint = {}
        for i in lines:
            if len(i) > 5 and i[:6] == b'FLIPME':
                current_pc = int(i[6:])
                recording = True
            if len(i) > 8 and i[:9] == b'FLIPMEEND':
                recording = False
            if recording:
                if b'(declare-fun' in i:
                    continue
                if b'(check-sat)' in i:
                    cmp_constraint[current_pc] = current_constraint
                    current_constraint = b''
                    continue
                current_constraint += i
        return cmp_constraint

    @staticmethod
    def __parse_output_path(lines: [bytes]):
        recording = False
        current_pc = -1
        current_constraint = b''
        path_constraints = {}
        bvs = set()
        for i in lines:
            if len(i) > 1 and i[:2] == b'BB':
                current_pc = int(i[2:])
                recording = True
            if len(i) > 4 and i[:5] == b'BBEND':
                recording = False
            if recording:
                if b'(declare-fun' in i:
                    bvs.add(i)
                    continue
                if b'(check-sat)' in i:
                    path_constraints[current_pc] = current_constraint
                    current_constraint = b''
                    continue
                current_constraint += i
        return bvs, path_constraints

    def __parse_output(self, lines: bytes):
        lines = lines.split(b"\n")
        bvs, path_constraints = self.__parse_output_path(lines)
        cmp_constraint = self.__parse_output_flipme(lines)
        return bvs, path_constraints, cmp_constraint

    # get a list of [path constraints] that has pc in pc_wanted_range
    @staticmethod
    def __find_last_path_node(path_constraints: dict, pc_wanted_range):
        result = []
        last_pc = -1
        for pc in sorted(path_constraints.keys()):
            if pc_wanted_range[0] < pc < pc_wanted_range[1]:
                if last_pc == -1:
                    result.append(b"")
                else:
                    result.append(path_constraints[last_pc])
            last_pc = pc
        return result

    # get a list of [cmp constraints] that has pc in pc_wanted_range
    @staticmethod
    def __find_last_cmp_pc(cmp_constraints_pcs: dict, pc_wanted_range):
        result = []
        for pc in cmp_constraints_pcs:
            if pc_wanted_range[0] < pc < pc_wanted_range[1]:
                result.append(pc)
        return result

    # find a path node to stop => find a cmp cons => flip cmp cons & concat
    def __get_constraint(self, flip_pc_range, bvs, path_constraints, cmp_constraint):
        path_cons = self.__find_last_path_node(path_constraints, flip_pc_range)
        cmp_cons = self.__find_last_cmp_pc(cmp_constraint, flip_pc_range)
        assert len(path_cons) == len(cmp_cons)
        if not path_cons:
            print(f"[QSYM] {str(flip_pc_range)} branch is constant")
        for path, cmp in zip(path_cons, cmp_cons):
            yield to_smt2(bvs, path + negate_smt2(cmp))

    # conduct concolic execution and flip constraints in flip_pc_range while preserving others
    def flip_it(self, testcase_content, flip_pc_range):
        result = self.__run_qsym_remote(testcase_content)
        bvs, path_constraints, cmp_constraint = self.__parse_output(result)
        for to_be_solved in self.__get_constraint(flip_pc_range, bvs, path_constraints, cmp_constraint):
            if len(to_be_solved) == 0:
                print("[Solver] Conc exec gives nothing")
                continue
            solution = solve_smt(to_be_solved)
            if not solution:
                continue
            yield solution
