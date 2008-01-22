!include <Win32.Mak>

# . is ...\pismere\athena\auth\krb5\src\ccapi\lib\win
CCAPI = ..\..
CO      = $(CCAPI)\common
COWIN   = $(CCAPI)\common\win
CCUTIL  = $(CCAPI)\common\win\OldCC             
LIBDIR  = $(CCAPI)\lib
LIBWIN  = $(LIBDIR)\win
K5SRC   = $(CCAPI)\..
POSIX   = $(K5SRC)\lib\krb5\posix
OLDCC   = $(LIBWIN)\OldCC

INC     = -I.. -I$(CO) -I$(COWIN) -I$(K5SRC)\include -I..\..\..\util\et -I$(OLDCC) \
    -I$(LIBWIN) -I$(CCUTIL)
MIDLI   = /I $(K5SRC)\include /I. /I$(COWIN) /I$(CO) 

!if "$(CPU)" == "i386"
cflags = $(cflags) /EHsc /MDd -D_CRTAPI1=_cdecl -D_CRTAPI2=_cdecl -DWINVER=0x0501 -D_WIN32_WINNT=0x0501 \
$(INC) -D_CRT_SECURE_NO_WARNINGS
!else
cflags = $(cflags) /W3 -D_CRTAPI1= -D_CRTAPI2= $(INC)
!endif

!if "$(PREPROCESS)" == "P"
cflags = $(cflags) -P
!endif

all : ccapi.dll

common = cci_array_internal.obj cci_cred_union.obj cci_debugging.obj cci_identifier.obj \
    cci_message.obj cci_stream.obj 
    
commonwin = cci_os_debugging.obj \
            cci_os_identifier.obj \
            tls.obj \
            win-utils.obj

dll =   ccapi_ccache.obj \
        ccapi_ccache_iterator.obj \
        ccapi_context.obj \
        ccapi_context_change_time.obj \
        ccapi_credentials.obj \
        ccapi_credentials_iterator.obj \
        ccapi_ipc.obj \
        ccapi_string.obj 

dllwin =    ccs_reply_s.obj \
            ccs_reply_proc.obj \
            ccs_request_c.obj            
            
dllwincxx = ccapi_os_ipc.obj \
            dllmain.obj
            
oldcc   =   client.obj \
            rpc.obj 
            
utils   =   ccutils.obj

utilscxx =  init.obj \
            secure.obj \
            util.obj


linkobjs = $(common) $(commonwin) $(dll) $(dllwin) $(dllwincxx) $(oldcc) $(utils) $(utilscxx)

#includes = 

# Main program:
ccapi.dll : $(linkobjs) ccapi.def
    $(link) $(linkdebug) $(conflags) -out:ccapi.dll /DEF:ccapi.def /implib:ccapi.lib $(dlllflags) \
        $(linkobjs) rpcrt4.lib kernel32.lib user32.lib $(conlibsdll) 


ccs_request.h ccs_request_c.c ccs_request_s.c : $(COWIN)\ccs_request.idl $(COWIN)\ccs_request.acf
    midl $(MIDL_OPTIMIZATION) $(MIDLI) -oldnames -cpp_cmd $(cc) -cpp_opt "-E" \
    $(COWIN)\ccs_request.idl

ccs_reply.h   ccs_reply_c.c   ccs_reply_s.c   : $(COWIN)\ccs_reply.idl   $(COWIN)\ccs_reply.acf
    midl $(MIDL_OPTIMIZATION) $(MIDLI) -oldnames -cpp_cmd $(cc) -cpp_opt "-E" -I. -I$(COWIN) \
    $(COWIN)\ccs_reply.idl

$(common) : $(CO)\$*.c
   $(cc) $(cdebug) $(cflags) $(cvarsdll) $(CO)\$*.c

$(commonwin) : $(COWIN)\$*.c
   $(cc) $(cdebug) $(cflags) $(cvarsdll) $(COWIN)\$*.c

$(dll) : $(LIBDIR)\$*.c
   $(cc) $(cdebug) $(cflags) $(cvarsdll) $(LIBDIR)\$*.c

$(dllwin) : $*.c ccs_reply.h ccs_request.h
   $(cc) $(cdebug) $(cflags) $(cvarsdll) $(LIBWIN)\$*.c

$(dllwincxx) : $*.cxx ccs_reply.h ccs_request.h
   $(cc) $(cdebug) $(cflags) $(cvarsdll) $(LIBWIN)\$*.cxx

$(oldcc) : $(OLDCC)\$*.cxx
   $(cc) $(cdebug) $(cflags) $(cvarsdll) $(OLDCC)\$*.cxx

$(utils) : $(CCUTIL)\$*.c
   $(cc) $(cdebug) $(cflags) $(cvarsdll) $(CCUTIL)\$*.c

$(utilscxx) : $(CCUTIL)\$*.cxx
   $(cc) $(cdebug) $(cflags) $(cvarsdll) $(CCUTIL)\$*.cxx



# Clean up everything
cleanall : clean
    -del *.dll

# Clean up everything but the .EXEs
clean :
    -del *.obj
    -del *.map
