all: solver_avx1 solver_avx2 quickbench_avx1 quickbench_avx2

solver_avx1: solver.c equihash_avx1.o
	gcc -o solver_avx1 solver.c equihash_avx1.o

solver_avx2: solver.c equihash_avx2.o
	gcc -o solver_avx2 solver.c equihash_avx2.o

quickbench_avx1: quickbench.c equihash_avx1.o
	gcc -o quickbench_avx1 quickbench.c equihash_avx1.o

quickbench_avx2: quickbench.c equihash_avx2.o
	gcc -o quickbench_avx2 quickbench.c equihash_avx2.o

.PHONY: clean
clean:
	rm solver_avx1 solver_avx2 quickbench_avx1 quickbench_avx2
