CC=cc
AR=ar r
RM=rm -f

# path to your OpenSSL installation
OPENSSL=/usr/local/ssl

INC=-I$(OPENSSL)/include
LDFLAGS=-L$(OPENSSL) -L./
LOADLIBES=-lyarrow -lcrypto #-lm

# options you want to use
DEF1=-DYARROW_SAVE_STATE -DYARROW_TRACE #-DYARROW_DETECT_FORK 
DEF2=-DYARROW_NO_MATHLIB 
DEF=$(DEF1) $(DEF2)

OPT=-g
#OPT=-O3

CFLAGS=$(OPT) $(DEF) $(INC)

LIB=libyarrow.a
OBJS=yarrow.o ystate.o yseed.o
EXES=ytest

ytest: ytest.o $(LIB)
	$(CC) $(LDFLAGS) ytest.o $(LOADLIBES) -o $@

$(LIB): $(OBJS)
	$(AR) $(LIB) $(OBJS)

test:	ytest
	./ytest

clean:
	$(RM) *.a *.o *~ *.bak $(EXES) core

distclean:	clean
	$(RM) seed TAGS

tags:
	etags *.c *.h 

# DO NOT DELETE

yarrow.o: yarrow.h ytypes.h yhash.h ycipher.h ylock.h ystate.h yexcep.h
yseed.o: yarrow.h ytypes.h yhash.h ycipher.h yexcep.h
ystate.o: yarrow.h ytypes.h yhash.h ycipher.h ystate.h yexcep.h
ytest.o: yarrow.h ytypes.h yhash.h ycipher.h yexcep.h
yarrow.o: ytypes.h yhash.h ycipher.h
ylock.o: yarrow.h ytypes.h yhash.h ycipher.h
