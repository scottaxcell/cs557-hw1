all:
	gcc -D_GNU_SOURCE -std=c99 -o sniffer sniffer.c -lpcap
dbg:
	gcc -Wall -g -D_GNU_SOURCE -std=c99 -o sniffer sniffer.c -lpcap
clean:
	rm -f sniffer
