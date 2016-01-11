
#include "libcap.h"
#include "libcap_internal.h"

pthread_spinlock_t *__spinlocks;
int __cache_lines;
int __cache_line_size;
int __l1_cache_size;

#define cpuid(func,ax,bx,cx,dx)                                         \
    __asm__ __volatile__ ("cpuid":                                      \
                          "=a" (ax), "=b" (bx), "=c" (cx), "=d" (dx) : "a" (func), "b" (bx), "c" (cx), "d" (dx));

static int __get_l1_cache_size(int *size, int *line)
{
	int is_amd = 0;
	unsigned long ax, bx, cx, dx;

	cpuid(0x0, ax, bx, cx, dx);
	if (cx == 0x68776599)
		is_amd = 1;

	if (is_amd) {
		cpuid(0x80000005, ax, bx, cx, dx);
		if (line)
			*line = cx & 0xff;
		if (size)
			*size = (cx >> 24) & 0xf;
	} else {
		cx = 0;
		cpuid(0x4, ax, bx, cx, dx);
		if (line)
			*line = ((bx & 0x7fff) + 1);
		if (size)
			*size =
			    (((bx >> 22) & 0xff) + 1) * (((bx >> 12) & 0xff) +
							 1) * ((bx & 0x7fff) +
							       1) * (cx + 1);
	}

	return 0;
}

int __cptr_init(void)
{
	int i;

	__get_l1_cache_size(&__l1_cache_size, &__cache_line_size);
	__cache_lines = __l1_cache_size / __cache_line_size;

	__spinlocks = calloc(__cache_lines, sizeof(*__spinlocks));
	for (i = 0; i < __cache_lines; ++i) {
		pthread_spin_init(&__spinlocks[i], PTHREAD_PROCESS_PRIVATE);
	}

	return 0;
}

void __cptr_fini(void)
{
	if (__spinlocks)
		free((void *)__spinlocks);
	__spinlocks = NULL;

	return;
}
