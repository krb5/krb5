# 
# Copyright 1993 OpenVision Technologies, Inc., All Rights Reserved.
# 
# $Id$
# $Source$
#

TOP = ..
include $(TOP)/config.mk/template

SRCS 	= keytab.c
OBJS	= keytab.o
PROG	= ovsec_edit_keytab

LIBS	= $(LIBADMCLNT) $(LIBCOM_ERR) $(LIBGSSAPI_KRB5) $(LIBRPCLIB) \
	$(LIBDYN) $(LIBDB) $(LIBKRB5) $(LIBCRYPTO) $(LIBISODE) \
	$(BSDLIB) $(NETLIB) 

expand InstallAdmin

PROG	= ovsec_edit_keytab.local
LIBS	= $(LIBADMSRV) $(LIBGSSAPI_KRB5) $(LIBKDB5) $(LIBKRB5) $(NDBMLIB) \
	  $(LIBRPCLIB) $(LIBDYN) $(LIBDB) $(LIBKRB5) $(LIBCRYPTO) \
	  $(LIBCOM_ERR) $(BSDLIB) $(NETLIB)

expand InstallAdmin

SUBDIRS = unit-test
expand SubdirTarget

