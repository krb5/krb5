#
#   WARNING    WARNING    WARNING    WARNING    WARNING    WARNING    WARNING
#
# This is NOT an automatically generated Makefile!  It is hand-crafted as a 
# bootstrap, may need editing for your system.  The BOOTSTRAPCFLAGS variable
# may be given at the top of the build tree for systems that do not define
# any machine-specific preprocessor symbols.
#

BOOTSTRAPCFLAGS = 
    CDEBUGFLAGS = -O
         CFLAGS = $(BOOTSTRAPCFLAGS) $(CDEBUGFLAGS)
          SHELL = /bin/sh
             RM = rm -f
           MAKE = make
         RM_CMD = $(RM) *.CKP *.ln *.BAK *.bak *.o core errs ,* *~ *.a \
			tags TAGS make.log
          NPROC = 1

imake::
	@echo "making imake with BOOTSTRAPCFLAGS=$(BOOTSTRAPCFLAGS)"

imake:: ccimake imake.c
	$(CC) -o imake $(CFLAGS) imake.c `./ccimake`

ccimake: ccimake.c
	$(CC) -o ccimake $(CFLAGS) ccimake.c

relink:
	$(RM) imake
	$(MAKE) $(MFLAGS) imake

clean:
	$(RM) ccimake imake
	$(RM_CMD) \#*

depend:


# for manual use

Makefile: imake
	imake -DNEWTOP=../

tags:

install:

install.man:

Makefiles:
