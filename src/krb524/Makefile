# Copyright 1993 by Geer Zolot Associates.  All Rights Reserved.
# 
# Export of this software from the United States of America may
# require a specific license from the United States Government.  It
# is the responsibility of any person or organization contemplating
# export to obtain such a license before exporting.
# 
# WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
# distribute this software and its documentation for any purpose and
# without fee is hereby granted, provided that the above copyright
# notice appear in all copies and that both that copyright notice and
# this permission notice appear in supporting documentation, and that
# the name of Geer Zolot Associates not be used in advertising or
# publicity pertaining to distribution of the software without specific,
# written prior permission.  Geer Zolot Associates makes no
# representations about the suitability of this software for any
# purpose.  It is provided "as is" without express or implied warranty.
# 
# $Id$

KRB5TOP = /ua/software/build/sun4/krb5.src.B2/src

# Library sources
SRCS	= conv_creds.c conv_princ.c conv_tkt.c conv_tkt_skey.c \
	encode.c misc.c globals.c sendmsg.c krb524_err.et
OBJS	= conv_creds.o conv_princ.o conv_tkt.o conv_tkt_skey.o \
	encode.o misc.o globals.o sendmsg.o krb524_err.o

GENS	= krb524_err.c krb524_err.h

# Server stuff.
LDFLAGS= -L. -L/usr/local/lib
LIBS	= -lkrb524 -lkdb5 -lkrb5 -lkrb -lcrypto /usr/local/lib/libdes.a \
	-lisode -lcom_err

CL_LIBS	= -lkrb524 -lkrb5 -lcrypto -lisode -lkrb -lcom_err

CC	= gcc
CFLAGS 	= -g -DUSE_MASTER -I. -I/usr/local/include

all: libkrb524.a krb524d test k524init

libkrb524.a: $(OBJS)
	ar cru libkrb524.a $(OBJS)
	ranlib libkrb524.a

test: libkrb524.a test.o
	$(CC) -o test $(LDFLAGS) test.o $(LIBS)

krb524d: libkrb524.a krb524d.o
	$(CC) -o krb524d krb524d.o $(LDFLAGS) $(LIBS)

k524init: libkrb524.a k524init.o
	$(CC) -o k524init $(LDFLAGS) k524init.o $(CL_LIBS)

krb524d.o: krb524d.c
	$(CC) -c $(CFLAGS) -I$(KRB5TOP)/include $*.c

test.o: test.c
	$(CC) -c $(CFLAGS) -I$(KRB5TOP)/include $*.c

depend: $(GENS)
	makedepend -- $(CFLAGS) -I$(KRB5TOP)/include -- $(SRCS) \
		test.c krb524d.c

clean:
	-rm -f libkrb524.a $(OBJS) $(GENS) core *~ *.bak #*
	-rm -f test krb524d k524init test.o krb524d.o k524init.o

krb524_err.c krb524_err.h: krb524_err.et
	compile_et krb524_err.et

.SUFFIXES: .et

# DO NOT DELETE THIS LINE -- make depend depends on it.
