TOP = ..
include $(TOP)/config.mk/template

PROG	= kadmin_create
SRCS	= kdb5_create.c kadm5_create.c string_table.c
OBJS	= kdb5_create.o kadm5_create.o string_table.o

LIBS =	$(LIBADMSRV) $(LIBRPCLIB) $(LIBKDB5) $(LIBKRB5_ALL) \
	$(LIBDYN) $(NDBMLIB) $(LIBDB) $(BSDLIB) $(NETLIB) 

expand InstallAdmin
expand Depend
