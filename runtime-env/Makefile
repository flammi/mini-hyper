.PHONY: disasm

runtime:
	gcc -nostdlib startup.S runtime.c interrupts.c test.c -Wl,-Tminimal.ld -o a.out

disasm:
	objdump --target=binary -m i386:x86-64 -D -Mintel a.out 
