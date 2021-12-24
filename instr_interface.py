import abc
import json


# Exec Tree
class Node:
    left = None
    right = None
    addr = 0
    left_prob = -1
    right_prob = -1
    is_comp = False
    visit_count = 1
    addr_range = None
    led_by = ""

    @staticmethod
    def to_addr(node):
        if node:
            return node.addr
        return 0

    def __str__(self):
        return f"left: {hex(self.to_addr(self.left))}; " \
               f"right: {hex(self.to_addr(self.right))}; " \
               f"comp: {self.is_comp}; " \
               f"vc: {self.visit_count}; " \
               f"left_prob: {self.left_prob}; " \
               f"right_prob: {self.right_prob};" \
               f"led_by: {self.led_by}" \
               f"addr_range: {hex(self.addr_range[0])} - {hex(self.addr_range[1])}"


class Instrumentation(abc.ABC):
    def __init__(self, executor):
        self.executor = executor
        self.execution_tree = {}  # addr -> Node
        self.corpus_traces = {}
        self.unsolvable = set()

    def build_execution_tree(self, new_testcase_filenames: [str]):
        pass

    def dump_execution_tree(self):
        print(json.dumps({hex(x): str(self.execution_tree[x]) for x in self.execution_tree}, sort_keys=True, indent=4))

    def __dfs_helper(self, current_node_addr, visited_nodes):
        if current_node_addr in visited_nodes:
            return
        visited_nodes.add(current_node_addr)
        current_node = self.execution_tree[current_node_addr]

        left_node = self.execution_tree[current_node_addr].left
        right_node = self.execution_tree[current_node_addr].right
        should_assign_prob = current_node.is_comp
        sum_of_children = 1  # prevent div by 0, todo: this causes left + right != 1

        if left_node is not None:
            self.__dfs_helper(left_node.addr, visited_nodes)
            sum_of_children += left_node.visit_count

        if right_node is not None:
            self.__dfs_helper(right_node.addr, visited_nodes)
            sum_of_children += right_node.visit_count

        if left_node is not None:
            current_node.left_prob = left_node.visit_count / sum_of_children
        else:
            current_node.left_prob = 3 / sum_of_children

        if right_node is not None:
            current_node.right_prob = right_node.visit_count / sum_of_children
        else:
            current_node.right_prob = 3 / sum_of_children

        if not should_assign_prob or sum_of_children < 30:
            current_node.left_prob = 1
            current_node.right_prob = 1

    def assign_prob(self):
        self.__dfs_helper(next(iter(self.execution_tree)), set())

    def __get_prob(self, parent, child):
        parent_node = self.execution_tree[parent]
        child_node = self.execution_tree[child]
        if parent_node.left and parent_node.left == child_node:
            return parent_node.left_prob
        if parent_node.right and parent_node.right == child_node:
            return parent_node.right_prob
        print(f"[Exec] {parent} {child} not in execution tree")
        assert False

    def __is_branch_missed(self, parent):
        parent_node = self.execution_tree[parent]
        return parent_node.right is None and parent_node.is_comp

    def __is_unsolvable(self, testcase_fn, flip_pcs):
        return (testcase_fn, flip_pcs[0], flip_pcs[1]) in self.unsolvable

    def add_unsolvable_path(self, testcase_fn, flip_pcs):
        self.unsolvable.add((testcase_fn, flip_pcs[0], flip_pcs[1]))

    def get_sorted_missed_path(self, num=10):
        missed_paths = []
        for filename in self.corpus_traces:
            trace = self.corpus_traces[filename]
            prob = 1
            trace_len = len(trace)
            for k, node in enumerate(trace):
                if k + 1 == trace_len:
                    break
                next_node = trace[k + 1]
                if self.__is_branch_missed(node.addr):
                    path_prob = prob * node.right_prob
                    if self.__is_unsolvable(filename, node.addr_range):
                        continue
                    missed_paths.append({
                        "flip": node.addr_range,
                        "prob": path_prob,
                        "fn": filename
                    })
                prob *= self.__get_prob(node.addr, next_node.addr)
        return sorted(missed_paths, key=lambda x: x["prob"])[:min(num, len(missed_paths))]
