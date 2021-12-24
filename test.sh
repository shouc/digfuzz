./build_afl.bash
clang -c -g angr_harness.c -o angr_harness.o
clang  -fsanitize-coverage=bb,trace-pc-guard,indirect-calls,trace-cmp,no-prune -fsanitize=address -g test.cc FuzzingEngine.a -o test.fuzz
clang -g angr_harness.o test.cc -o test.angr
