CC = gcc -g

CFLAGS = -O1 -Wall

OBJS = traceroute.o

all: traceroute

traceroute: $(OBJS)
	$(CC) $(CFLAGS) -o traceroute $(OBJS)

traceroute.o: traceroute.c

clean:
	rm -f traceroute.o

distclean:
	rm -f *~ *.o traceroute

