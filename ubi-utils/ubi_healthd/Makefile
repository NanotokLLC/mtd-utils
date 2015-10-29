CFLAGS=-Wall -Wextra -Werror -O3 -I../../include -I ../include -I../include -DGNU_SOURCE -std=gnu11
LDFLAGS=-L../../ubi-utils -lubi

SRCS=$(wildcard *.c)
OBJS=$(SRCS:.c=.o)
BIN=ubi_healthd

all: $(BIN)

$(OBJS): Makefile

$(BIN): $(OBJS) Makefile
	$(CC) $(CFLAGS) -o $(BIN) $(OBJS) $(LDFLAGS)

.c.o:
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	$(RM) $(BIN)
	$(RM) $(OBJS)

.PHONY: clean

