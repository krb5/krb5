CC = cc
CCFLAGS = -g -I../../include
LIBS = -L../../lib -lkrb5 -lcom_err

all: krb5_encode_test krb5_decode_test

ENCOBJS = krb5_encode_test.o ktest.o ktest_equal.o utility.o asn1buf.o
krb5_encode_test: $(ENCOBJS)
	$(CC) $(CCFLAGS) -o krb5_encode_test $(ENCOBJS) $(LIBS)

DECOBJS = krb5_decode_test.o ktest.o ktest_equal.o
krb5_decode_test: $(DECOBJS)
	$(CC) $(CCFLAGS) -o krb5_decode_test $(DECOBJS) $(LIBS)

clean:
	rm -f *~ *.o krb5_encode_test krb5_decode_test


################ Dependencies ################
asn1buf.o: asn1buf.h
asn1buf.h: krbasn1.h
krb5_decode_test.o: ktest.h utility.h ktest_equal.h debug.h
krb5_encode_test.o: utility.h krb5_encode_test_body.c
krb5_encode_test_body.o: ktest.h debug.h
ktest.o: ktest.h utility.h
ktest_equal.o: ktest_equal.h
utility.o: utility.h
utility.h: krbasn1.h asn1buf.h
##############################################

################ Inference Rules ################
.SUFFIXES: .o .c

.c.o:
	$(CC) -c $(CCFLAGS) $<
#################################################
