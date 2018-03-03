CC = gcc
LD = gcc
CFLAGS = -g -Wall
LDFLAGS =
RM = /bin/rm -f
OBJS = trackermon.o
PROG = trckrmn

all: $(PROG)

$(PROG): $(OBJS)
				$(LD) $(LDFLAGS) $(OBJS) -o $(PROG)

trackermon.o: trackermon.c
				$(CC) $(CFLAGS) -c trackermon.c

clean:
				$(RM) $(PROG) $(OBJS)
