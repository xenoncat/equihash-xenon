all: solver_avx1 solver_avx2 quickbench_avx1 quickbench_avx2

solver_avx1:
	gcc -fno-pie -image_base 400000 -pagezero_size 1000 -o solver_avx1 solver.c equihash_avx1_m.o

solver_avx2:
	gcc -fno-pie -image_base 400000 -pagezero_size 1000 -o solver_avx2 solver.c equihash_avx2_m.o

quickbench_avx1:
	gcc -fno-pie -image_base 400000 -pagezero_size 1000 -o quickbench_avx1 quickbench.c equihash_avx1_m.o

quickbench_avx2:
	gcc -fno-pie -image_base 400000 -pagezero_size 1000 -o quickbench_avx2 quickbench.c equihash_avx2_m.o

.PHONY: clean
clean:
	rm solver_avx1 solver_avx2 quickbench_avx1 quickbench_avx2 equihash_avx1_m.o equihash_avx2_m.0
