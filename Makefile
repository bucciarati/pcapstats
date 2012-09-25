CFLAGS += -std=c99 -ggdb3 -W -Wall -Wextra
LDFLAGS += -lpcap

.PHONY: all clean

all: pcapstats

clean:
	$(RM) pcapstats
