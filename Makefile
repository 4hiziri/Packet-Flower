bin/ra: ra.c
	gcc -Wall -O2 -o bin/ra ra.c -lnet
dump: ra-dump.c
	gcc -Wall -O2 -o bin/ra-dump ra-dump.c -lpcap
