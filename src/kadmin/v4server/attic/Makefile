TOP = ../..
include $(TOP)/config.mk/template

ifdef KRB5B4
CFLAGS += -DKRB5B4 $(D_POSIX_SIGNALS)
endif

PROG	:= ovsec_v4adm_server

SRCS	:= kadm_server.c admin_server.c kadm_ser_wrap.c \
	kadm_stream.c kadm_supp.c acl_files.c 

OBJS 	:= kadm_server.o admin_server.o kadm_ser_wrap.o \
	kadm_stream.o kadm_supp.o acl_files.o

LIBS 	:= $(LIBADMCLNT) $(LIBRPCLIB) $(LIBGSSAPI_KRB5) $(LIBKRB5) \
	$(LIBKADM) $(LIBKRB) $(LIBDES425) $(LIBKDB5) \
	$(LIBCRYPTO) $(LIBISODE) \
	$(LIBDYN) $(LIBDB) $(LIBCOM_ERR) $(NDBMLIB) $(NETLIB) $(BSDLIB)

ifdef WAIT_USES_INT
WAIT_FLAGS = -DWAIT_USES_INT
endif
ifdef OPEN_NEEDS_FCNTL
FCNTL_FLAGS = -DNEED_SYS_FCNTL_H
endif

# XXX the -D's should probably be moved somewhere; in krb5.4.2 they 
# are in osconf.h
CFLAGS	:= -DOVSEC_KADM \
	-DKADM_SYSLOG="\"/krb5/admin_server.syslog\"" \
	-DDEFAULT_ACL_DIR="\"/krb5\"" $(WAIT_FLAGS) $(FCNTL_FLAGS) \
	$(CFLAGS)

expand InstallServer
expand Depend

SUBDIRS = unit-test
expand SubdirTarget
