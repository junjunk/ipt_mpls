CFLAGS = -O2 -Wall

all: libipt_MARKMPLS.so

lib%.so: lib%.o
	gcc -shared -fPIC -o $@ $^;

lib%.o: lib%.c
	gcc ${CFLAGS} -D_INIT=lib$*_init -fPIC -c -o $@ $<;

clean:
	rm -f *.o *.so

install: all
	cp *.so /lib/xtables/
