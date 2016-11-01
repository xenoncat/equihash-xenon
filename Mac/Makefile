OBJCONV ?= ./objconv

all: equihash_avx1.o equihash_avx2.o

equihash_avx1.o: ../Linux/asm/equihash_avx1.o
	$(OBJCONV) -fmacho -nu ../Linux/asm/equihash_avx1.o equihash_avx1.o

equihash_avx2.o: ../Linux/asm/equihash_avx2.o
	$(OBJCONV) -fmacho -nu ../Linux/asm/equihash_avx2.o equihash_avx2.o
