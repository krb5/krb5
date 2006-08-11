default: krb5

d = $(CURDIR)

ptest: ptest.c
	cc -I$(d)/trunk/src/include \
		-L$(d)/trunk/src/lib \
		-g ptest.c -o ptest -lkrb5 -lcom_err

tags:
	etags `find . -name "*.[ch]" -print`

krb5conf:
	cd trunk/src && ./util/reconf --force && ./configure

krb5:
	cd trunk/src && make
