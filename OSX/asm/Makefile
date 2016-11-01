all: equihash_avx1 equihash_avx2

equihash_avx1:
	./fasm equihash_avx1.asm -m 500000
	./objconv -fmacho64 equihash_avx1.o equihash_avx1_m.o
	cp equihash_avx1_m.o ../demo/equihash_avx1_m.o

equihash_avx2:
	./fasm equihash_avx2.asm -m 500000
	./objconv -fmacho64 equihash_avx2.o equihash_avx2_m.o
	cp equihash_avx2_m.o ../demo/equihash_avx2_m.o

.PHONY: clean
clean:
	rm equihash_avx1_m.o equihash_avx2_m.o
