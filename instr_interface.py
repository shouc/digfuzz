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
        return f"left: {self.to_addr(self.left)}; " \
               f"right: {self.to_addr(self.right)}; " \
               f"comp: {self.is_comp}; " \
               f"vc: {self.visit_count}; " \
               f"left_prob: {self.left_prob}; " \
               f"right_prob: {self.right_prob};" \
               f"led_by: {self.led_by}" \
               f"addr_range: {self.addr_range}"


class Instrumentation(abc.ABC):
    def __init__(self, executor):
        self.executor = executor
        self.execution_tree = {}  # addr -> Node

    def build_execution_tree(self, new_testcase_filenames: [str]):
        pass

    def dump_execution_tree(self):
        print(json.dumps({x: str(self.execution_tree[x]) for x in self.execution_tree}, sort_keys=True, indent=4))
