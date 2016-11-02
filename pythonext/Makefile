#
# Run assembler.
#

FASM = ../Linux/asm/fasm
FASMOPT = -m 512000

ASMDIR = ../Linux/asm
SOURCEFILES = $(wildcard $(ASMDIR)/*.asm) $(wildcard $(ASMDIR)/*.inc)

all: equihash_lib_avx1.o equihash_lib_avx2.o

equihash_lib_avx1.o: $(SOURCEFILES)
	$(FASM) $(FASMOPT) $(ASMDIR)/equihash_lib_avx1.asm $@

equihash_lib_avx2.o: $(SOURCEFILES)
	$(FASM) $(FASMOPT) $(ASMDIR)/equihash_lib_avx2.asm $@

clean:
	$(RM) *.o

.PHONY: all clean

