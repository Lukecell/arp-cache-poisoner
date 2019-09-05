SRCS = $(wildcard src/*.c)
OBJS = $(bin/out)

INSTALL:
	$(CC) -o bin/out $(SRCS)

CLEAN:
	$rrm bin/out
