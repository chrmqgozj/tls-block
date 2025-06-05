LDLIBS += -lpcap -lnet

all: tls-block

tls-block: tls-block.cpp

clean:
	rm -f main *.o
