TOP = ..
include $(TOP)/config.mk/template

PROG	= kadmin
SRCS	= kadmin.c kadmin_ct.c ss_wrapper.c getdate.c keytab.c
OBJS	= kadmin.o kadmin_ct.o ss_wrapper.o getdate.o keytab.o
LIBS	= $(LIBADMCLNT) $(LIBRPCLIB) $(LIBGSSAPI_KRB5) $(LIBKRB5_ALL) \
	$(LIBSS) $(LIBDYN) $(LIBDB) $(NDBMLIB) $(BSDLIB) $(NETLIB)
DEPENDS	= kadmin_ct.c getdate.c

expand NormalProgram

PROG	= kadmin.local
LIBS	= $(LIBADMSRV) $(LIBRPCLIB) $(LIBGSSAPI_KRB5) $(LIBKDB5) \
	$(LIBKRB5_ALL) $(LIBSS) $(LIBDYN) $(LIBDB) $(NDBMLIB) \
	$(BSDLIB) $(NETLIB) $(REGEXLIB)

expand NormalProgram

depend:: $(SRCS)
clean:: ; -rm -f getdate.c y.tab.h kadmin_ct.c

install::
	$(INSTCMD) kadmin.1 $(INSTALL_MANDIR)/cat1/kadmin.1

# needed until we run makedepend
kadmin_ct.c: kadmin_ct.ct
kadmin_ct.o: kadmin_ct.c
