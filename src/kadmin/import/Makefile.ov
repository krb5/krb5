TOP = ..
include $(TOP)/config.mk/template
CFLAGS := $(CFLAGS)

# The next line *shouldn't* work, because the : should be a ::.
# However, it does work, and if I change it to :: gmake does really
# weird things.
ovsec_adm_import: import_err.h

depend:: import_err.h

PROG := kadm5_import
OBJS := ovsec_adm_import.o import_err.o import.o strtok.o misc.o
SRCS := ovsec_adm_import.c import.c import_err.et strtok.c misc.c
ETABLES := import_err.et

LIBS = $(LIBADMSRV) $(LIBRPCLIB) $(LIBKDB5) $(LIBKRB5_ALL) $(LIBDYN) $(LIBDB)

expand ErrorTables
expand InstallAdmin
expand Depend

SUBDIRS = unit-test
expand SubdirTarget
