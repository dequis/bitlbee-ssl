CFLAGS ?= -g
LDFLAGS += -shared -fPIC $(shell pkg-config --cflags bitlbee) -lgio-2.0
DEST ?= $(shell pkg-config --variable plugindir bitlbee)


%.so: %.c
	$(CC) $(CFLAGS) $(LDFLAGS) $< -o $@

all: bitlbee_ssl.so

clean:
	rm -f bitlbee_ssl.so

install:
	install -m 0755 -p bitlbee_ssl.so $(DEST)

.PHONY: all clean install
