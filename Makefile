LDLIBS += -lpcap

all: pcap-test

pcap-test: print.o main.o
	gcc -o pcap-test print.o main.o -lpcap

main.o: libnet.h print.h main.c

print.o: libnet.h print.h print.c

clean:
	rm -f pcap-test
	rm -f *.o
