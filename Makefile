all: arp_test

arp_test: arp_test.c
			gcc -W -Wall -o arp_test arp_test.c -lpcap

clean:
		rm arp_test | rm *.out
