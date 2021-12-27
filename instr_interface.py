import abc
import json
import angr


# Exec Tree
class Node:
    def __init__(self):
        self.children = set()
        self.children_prob = []
        self.max_encounter_child = {}
        self.addr = 0
        self.is_comp = False
        self.visit_count = 1
        self.addr_range = None
        self.led_by = ""

    @staticmethod
    def to_addr(node):
        if node:
            return node.addr
        return 0

    def __hash__(self):
        return self.addr

    def __str__(self):
        return f"comp: {self.is_comp}; " \
               f"vc: {self.visit_count}; " \
               f"children: {self.children}; " \
               f"prob: {self.children_prob};" \
               f"led_by: {self.led_by}" \
               f"addr_range: {hex(self.addr_range[0])} - {hex(self.addr_range[1])}"


class UnknownNode(Node):
    pass


class Instrumentation(abc.ABC):
    def __init__(self, executor):
        self.executor = executor
        self.execution_tree = {}  # addr -> Node
        self.corpus_traces = {}
        self.dfs_visited_nodes = set()
        self.unsolvable = set()
        self.solved = set()
        self.basic_block = {}  # BB start => size
        self.__get_basic_block_size()

    def __get_basic_block_size(self):
        p = angr.Project(self.executor.uninstrumented_path, load_options={'auto_load_libs': False})
        cfg = p.analyses.CFGFast()
        for key in cfg.kb.functions:
            for bb in cfg.kb.functions[key].blocks:
                self.basic_block[bb.addr] = bb.size

    def build_execution_tree(self, new_testcase_filenames: [str]):
        pass

    def dump_execution_tree(self):
        print(json.dumps({hex(x): str(self.execution_tree[x]) for x in self.execution_tree}, sort_keys=True, indent=4))

    def assign_prob(self):
        for addr, current_node in self.execution_tree.items():
            should_assign_prob = current_node.is_comp
            sum_of_children = 1  # prevent div by 0, todo: this causes left + right != 1

            for child_node_addr in current_node.children:
                child_node = self.execution_tree[child_node_addr]
                sum_of_children += child_node.visit_count

            for child_node_addr in current_node.children:
                child_node = self.execution_tree[child_node_addr]
                current_node.children_prob.append(child_node.visit_count / sum_of_children)

            while len(current_node.children_prob) < 2:
                current_node.children_prob.append(3 / sum_of_children)

            if not should_assign_prob or sum_of_children < 30:
                current_node.children_prob = [1.0 for _ in range(len(current_node.children_prob))]

    def __get_prob(self, parent, child):
        parent_node = self.execution_tree[parent]
        child_node_addr = self.execution_tree[child].addr
        for k, _child_addr in enumerate(parent_node.children):
            if _child_addr == child_node_addr:
                return parent_node.children_prob[k]
        print(f"[Exec] {parent} {child} not in execution tree")
        assert False

    def __is_branch_missed(self, parent_addr, child_addr, nth=0):
        hit_count = nth + 1
        parent_node = self.execution_tree[parent_addr]
        return (
                   len(parent_node.children) < 2
                   or hit_count not in parent_node.max_encounter_child[child_addr]
               ) and parent_node.is_comp

    def __should_i_solve(self, testcase_fn, flip_pcs, nth=0):
        return ((testcase_fn, flip_pcs[0], flip_pcs[1], nth) not in self.unsolvable) and \
               ((testcase_fn, flip_pcs[0], flip_pcs[1], nth) not in self.solved)

    def add_unsolvable_path(self, testcase_fn, flip_pcs, nth=0):
        self.unsolvable.add((testcase_fn, flip_pcs[0], flip_pcs[1], nth))

    def add_solved_path(self, testcase_fn, flip_pcs, nth=0):
        self.solved.add((testcase_fn, flip_pcs[0], flip_pcs[1], nth))

    def get_sorted_missed_path(self, num=10):
        missed_paths = []
        for filename in self.corpus_traces:
            hit_counts = {}
            trace = self.corpus_traces[filename]
            prob = 1
            trace_len = len(trace)
            for k in range(1, trace_len - 1):
                node = trace[k]
                next_node = trace[k + 1]
                prev_node = trace[k - 1]

                hit_counts[node] = hit_counts[node] + 1 if node in hit_counts else 1
                nth = hit_counts[node] - 1
                if self.__is_branch_missed(node.addr, next_node.addr, nth=nth):
                    path_prob = prob * node.children_prob[-1]
                    flip_it = prev_node.addr_range
                    if not self.__should_i_solve(filename, flip_it, nth=nth):
                        continue
                    missed_paths.append({
                        "flip": flip_it,
                        "prob": path_prob,
                        "fn": filename,
                        "nth": nth
                    })
                prob *= self.__get_prob(node.addr, next_node.addr)
        return sorted(missed_paths, key=lambda x: x["prob"])[:min(num, len(missed_paths))]
