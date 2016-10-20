//compile with
//gcc -o quickbench quickbench.c equihash_avx2.o
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <mach/mach_time.h>

#define CONTEXT_SIZE 178033152
#define ITERATIONS 10

#define ORWL_NANO (+1.0E-9)
#define ORWL_GIGA UINT64_C(1000000000)

static double orwl_timebase = 0.0;
static uint64_t orwl_timestart = 0;

struct timespec orwl_gettime(void){
	if (!orwl_timestart) {
		mach_timebase_info_data_t tb = { 0 };
		mach_timebase_info(&tb);
		orwl_timebase = tb.numer;
		orwl_timebase /= tb.denom;
		orwl_timestart = mach_absolute_time();
	}
	struct timespec t;
	double diff = (mach_absolute_time() - orwl_timestart) * orwl_timebase;
	t.tv_sec = diff * ORWL_NANO;
	t.tv_nsec = diff - (t.tv_sec * ORWL_GIGA);
	return t;
}

//Linkage with assembly
//EhPrepare takes in 136 bytes of input. The remaining 4 bytes of input is fed as nonce to EhSolver.
//EhPrepare saves the 136 bytes in context, and EhSolver can be called repeatedly with different nonce.
void EhPrepare(void *context, void *input);
int32_t EhSolver(void *context, uint32_t nonce);
extern char testinput[];

int main(void)
{
	void *context_alloc, *context, *context_end;
	uint32_t *pu32;
	uint64_t *pu64, previous_rdtsc;
	uint8_t inputheader[144];	//140 byte header
	FILE *infile, *outfile;
	struct timespec time0, time1;
	long t0, t1;
	int32_t numsolutions, total_solutions;
	uint32_t nonce, delta_time, total_time;
	int i, j;

	context_alloc = malloc(CONTEXT_SIZE+4096);
	context = (void*) (((long) context_alloc+4095) & -4096);
	context_end = context + CONTEXT_SIZE;

	infile = 0;
	infile = fopen("input.bin", "rb");
	if (infile) {
		puts("Reading input.bin");
		fread(inputheader, 140, 1, infile);
		fclose(infile);
	} else {
		puts("input.bin not found, use sample data (beta1 testnet block 2)");
		memcpy(inputheader, testinput, 140);
	}


	EhPrepare(context, (void *) inputheader);

	//Warm up, timing not taken into average
	nonce = 0;
	time0 = orwl_gettime();
	numsolutions = EhSolver(context, nonce);
	time1 = orwl_gettime();
	delta_time = (uint32_t) ((time1.tv_sec * 1000000000 + time1.tv_nsec)
			- (time0.tv_sec * 1000000000 + time0.tv_nsec))/1000000;
	printf("(Warm up) Time: %u ms, solutions: %u\n", delta_time, numsolutions);

	printf("Running %d iterations...\n", ITERATIONS);
	nonce = 58;	//arbritary number to get 19 solutions in 10 iterations (to match 1.88 solutions per run)
	total_time = total_solutions = 0;
	for (i=0; i<ITERATIONS; i++) {
		time0 = orwl_gettime();
		numsolutions = EhSolver(context, nonce);
		time1 = orwl_gettime();
		nonce++;
		delta_time = (uint32_t) ((time1.tv_sec * 1000000000 + time1.tv_nsec)
				- (time0.tv_sec * 1000000000 + time0.tv_nsec))/1000000;
		total_time += delta_time;
		total_solutions += numsolutions;
		printf("Time: %u ms, solutions: %u\n", delta_time, numsolutions);
	}

	printf("Average time: %d ms; %.3f Sol/s\n", total_time/ITERATIONS, (double) 1000.0*total_solutions/total_time);

	free(context_alloc);
	return 0;
}
