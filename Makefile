bin/ra: ra.c
	gcc -Wall -O2 -o bin/ra ra.c -lnet
bin/dump: ra-dump.c
	gcc -Wall -O2 -o bin/ra-dump ra-dump.c -lpcap
get_dns: get_dns.c
	gcc get_dns.c -Wall -O2 -pthread -I/usr/include/libnm -I/usr/include/glib-2.0 -I/usr/lib/x86_64-linux-gnu/glib-2.0/include -lnm -lgio-2.0 -lgobject-2.0 -lglib-2.0 -o bin/get_dns
