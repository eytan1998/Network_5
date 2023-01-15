.PHONY: clean all

all: Sniffer Spoofer Sniffer_Spoofer Gateway

Gateway: Gateway.c
	gcc Gateway.c -o $@
clean:
	rm -f Sniffer Spoofer Sniffer_Spoofer Gateway

Sniffer_Spoofer: Sniffer_Spoofer.c
	gcc Sniffer_Spoofer.c -o $@  -lpcap

Sniffer: Sniffer.c
	gcc Sniffer.c -o $@  -lpcap

Spoofer: Spoofer.c
	gcc Spoofer.c -o $@  -lpcap
