TOP = ..
include $(TOP)/config.mk/template

CFLAGS := $(CFLAGS) -DUSE_KADM5_API_VERSION=1

# This used as a string table, not an error table
ETABLES = kpasswd_strings.et
expand ErrorTables

kpasswd.o: kpasswd_strings.h
depend:: kpasswd_strings.h

PROG	= kpasswd
SRCS	= tty_kpasswd.c kpasswd.c kpasswd_strings.c
OBJS	= tty_kpasswd.o kpasswd.o kpasswd_strings.o
LIBS	= $(LIBADMCLNT) $(LIBCOM_ERR) $(LIBGSSAPI_KRB5) $(LIBRPCLIB) \
	$(LIBDYN) $(LIBDB) $(LIBKDB5) $(LIBKRB5) $(LIBCRYPTO) \
	$(LIBISODE) $(NDBMLIB) $(BSDLIB) $(NETLIB)

expand NormalProgram

ifndef OMIT_XM_KPASSWD
PROG	= xm_kpasswd
CFLAGS	:= -I$(XM_INC) -I$(XT_INC) -I$(X_INC) $(CFLAGS)
SRCS	:= xm_kpasswd.c kpasswd.c kpasswd_strings.c
OBJS	:= xm_kpasswd.o kpasswd.o kpasswd_strings.o
LIBS	:= $(LIBS) $(XM_LIB) $(XT_LIB) $(X_LIB) $(REGEXLIB)

expand NormalProgram
endif

SUBDIRS = unit-test

expand SubdirTarget
