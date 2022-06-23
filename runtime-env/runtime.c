#include <stddef.h>

// Taken from klibc: https://kernel.googlesource.com/pub/scm/libs/klibc/klibc/+/refs/heads/master/usr/klibc/strlen.c
size_t strlen(const char *s)
{
	const char *ss = s;
	while (*ss)
		ss++;
	return ss - s;
}

void runtime_log(char* log) {
	long long len = strlen(log);
	int ret;
	__asm__("out %%eax, $0x13" : "=r" (log));
}
