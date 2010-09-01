# Dummy non-portable build system for sample password quality plugin.

INCLUDES = -I/path/to/krb5/prefix/include

all: pwqual_combo.so

pwqual_combo.so: combo.so
	gcc -shared -fPIC -o $@ combo.so

combo.so: combo.c
	gcc -fPIC -DSHARED $(INCLUDES) -g -c combo.c -o $@

clean:
	rm -f combo.so pwqual_combo.so
