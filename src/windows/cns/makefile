# makefile: Constructs the Kerberos for Windows ticket manager
# Works for both k4 and k5 releases.
#
NAME 	 = cns
OBJS 	 = cns.obj tktlist.obj

##### Options
DEBUG 	 = 1
!IF ! defined(KVERSION)
KVERSION = 5
!endif
KRB 	 = KRB$(KVERSION)

!if $(KVERSION) == 4
BUILDTOP = ..
LIBDIR 	 = $(BUILDTOP)\lib\krb
KLIB 	 = $(LIBDIR)\kerberos.lib 
WLIB 	 = $(LIBDIR)\winsock.lib
INCLUDES = /I$(BUILDTOP)\include
!endif

!if $(KVERSION) == 5
BUILDTOP =..\..
LIBDIR	 = $(BUILDTOP)\lib
KLIB	 = $(LIBDIR)\libkrb5.lib
WLIB	 = $(LIBDIR)\winsock.lib
INCLUDES = /I$(BUILDTOP)\include /I$(BUILDTOP)\include\krb5
!endif

##### C Compiler
CC 	 = cl
CFLAGS_RELEASE = /f- /nologo /W3 /AL /Gw /Gsy /Zp /O2 /DNDEBUG=1
CFLAGS_DEBUG   = /f  /nologo /W3 /AL /Gw /Gsy /Zp /O2 /Od /Zi
!if $(DEBUG)
CFLAGS 	 = $(CFLAGS_DEBUG) $(INCLUDES) /D$(KRB)=1
!else
CFLAGS 	 = $(CFLAGS_RELEASE) $(INCLUDES) /D$(KRB)=1
!endif

##### RC Compiler
RC 	 = rc
RFLAGS 	 = /nologo /D$(KRB)=1 $(INCLUDES)

##### Linker
LINK 	 = link
LIBS 	 = $(KLIB) $(WLIB)
SYSLIBS  = libw llibcew
!if $(DEBUG)
LFLAGS 	 = /co /nologo /nod /nopackcode /map:full
!else
LFLAGS 	 = /nologo /nod /nopackcode
!endif

all:: makefile $(NAME).exe

$(NAME).exe: $*.def $*.res $(OBJS) $(LIBS)
	$(LINK) $(LFLAGS) $(OBJS), $@, $*.map, $(LIBS) $(SYSLIBS), $*.def
	$(RC) $(RFLAGS) /k $*.res $@

$(OBJS) cns.res: cns.h tktlist.h

install:
	copy cns.exe ..\floppy

clean:: 
	if exist *.exe del *.exe
	if exist ..\floppy\cns.exe del ..\floppy\cns.exe
	if exist *.obj del *.obj
	if exist *.res del *.res
	if exist *.map del *.map
	if exist *.pdb del *.pdb
	if exist *.err del *.err

