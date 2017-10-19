fake-rdnss: nd-ra-rdnss.c
	gcc -Wall -O2 -o bin/fake-rdnss nd-ra-rdnss.c -lnet
