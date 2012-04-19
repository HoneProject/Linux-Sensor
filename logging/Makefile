
all: honelogd

clean:
	-rm -f honelogd

honelogd: honelogd.c
	gcc -Wall -O2 -I../src -o $@ $<

install: honelogd
	install $^ /usr/local/sbin

uninstall:
	rm /usr/local/sbin/honelogd

