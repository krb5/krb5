TOP = ../..
include $(TOP)/config.mk/template

SRCS	= kadmin.c kadmin_ct.ct ss_wrapper.c getdate.y
OBJS	= kadmin.o kadmin_ct.o ss_wrapper.o getdate.o
PROG	= cli_secure_admin

LIBS	= $(LIBADMCLNT) $(LIBRPCLIB) $(LIBGSSAPI_KRB5) $(LIBKRB5_ALL) \
	$(LIBSS) $(LIBDYN) $(LIBDB) $(NDBMLIB) $(BSDLIB) $(NETLIB)

expand NormalProgram
