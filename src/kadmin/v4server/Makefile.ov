TOP = ..
include $(TOP)/config.mk/template

ifdef KRB5B4
CFLAGS += -DKRB5B4 $(D_POSIX_SIGNALS)
endif

ETABLES = kadm_err.et
expand ErrorTables

depend:: kadm_err.h

PROG	:= ovsec_v4adm_server

SRCS	:= kadm_server.c admin_server.c kadm_ser_wrap.c \
	kadm_stream.c kadm_supp.c acl_files.c kadm_err.c

OBJS 	:= kadm_server.o admin_server.o kadm_ser_wrap.o \
	kadm_stream.o kadm_supp.o acl_files.o kadm_err.o

LIBS 	:= $(LIBADMCLNT) $(LIBRPCLIB) \
	$(LIBKADM) $(LIBKRB) $(LIBDES425) \
	$(LIBGSSAPI_KRB5) $(LIBKDB5) $(LIBKRB5_ALL) \
	$(LIBDYN) $(LIBDB) $(LIBCOM_ERR) $(NDBMLIB) $(NETLIB) $(BSDLIB)

ifdef WAIT_USES_INT
WAIT_FLAGS = -DWAIT_USES_INT
endif
ifdef OPEN_NEEDS_FCNTL
FCNTL_FLAGS = -DNEED_SYS_FCNTL_H
endif

CFLAGS	:= -DOVSEC_KADM -DUSE_KADM5_API_VERSION=1 \
	$(WAIT_FLAGS) $(FCNLT_FLAGS) -I. \
	-I$(TOP)/../include/kerberosIV -I$(TOP)/../../src/include/kerberosIV \
	$(CFLAGS)

expand InstallServer
expand Depend

SUBDIRS = unit-test
expand SubdirTarget
