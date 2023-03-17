CC = gcc -g
CFLAGS = -O3 

OBJS = traceroute.o

all: traceroute

traceroute: $(OBJS)
	$(CC) $(CFLAGS) -o traceroute $(OBJS)

traceroute.o: traceroute.c

clean:
	rm -f traceroute.o

distclean:
	rm -f *~ *.o traceroute
