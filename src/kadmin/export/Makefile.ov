TOP = ..
include $(TOP)/config.mk/template
# CFLAGS := $(CFLAGS) -Wall

# The next line *shouldn't* work, because the : should be a ::.
# However, it does work, and if I change it to :: gmake does really
# weird things.
ovsec_adm_export: export_err.h

depend:: export_err.h

PROG := kadm5_export
OBJS := ovsec_adm_export.o export.o export_err.o
SRCS := ovsec_adm_export.c export.c export_err.et
ETABLES := export_err.et
 
LIBS = $(LIBADMSRV) $(LIBRPCLIB) $(LIBKDB5) $(LIBKRB5_ALL) $(LIBDYN) $(LIBDB)

expand ErrorTables
expand InstallAdmin
expand Depend

SUBDIRS = unit-test
expand SubdirTarget
