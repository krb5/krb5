ptest: ptest.c
	cc -I/mit/amb/k5/trunk/src/include \
		-L/mit/amb/k5/trunk/src/lib \
		-g ptest.c -o ptest -lkrb5 -lcom_err

tags:
	etags `find . -name "*.[ch]" -print`

krb5conf:
	cd trunk/src && ./util/reconf --force && ./configure

krb5:
	cd trunk/src && make
