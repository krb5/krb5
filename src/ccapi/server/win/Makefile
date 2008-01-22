!include <Win32.Mak>

# . is ...\pismere\athena\auth\krb5\src\ccapi\server\win
CCAPI   = ..\..
CO      = $(CCAPI)\common
COWIN   = $(CCAPI)\common\win
CCUTIL  = $(CCAPI)\common\win\OldCC
LIBDIR  = $(CCAPI)\lib
LIBWIN  = $(CCAPI)\lib\win
K5SRC   = $(CCAPI)\..
POSIX   = $(K5SRC)\lib\krb5\posix

INC     = -I. -I.. -I$(CO) -I$(COWIN) -I$(K5SRC)\include -I..\..\..\util\et -I$(CCUTIL)

!if "$(CPU)" == "i386"
cflags = $(cflags) /EHsc -D_CRTAPI1=_cdecl -D_CRTAPI2=_cdecl -DWINVER=0x0501 -D_WIN32_WINNT=0x0501 \
$(INC) -MTd
!else
cflags = $(cflags) /W3 -D_CRTAPI1= -D_CRTAPI2= $(INC)
!endif

all : server

server : server.exe

common = cci_array_internal.obj cci_cred_union.obj cci_debugging.obj cci_identifier.obj \
    cci_message.obj cci_stream.obj 
    
commonwin = cci_os_debugging.obj \
            cci_os_identifier.obj \
            tls.obj \
            win-utils.obj

ccutils = ccutils.obj 

ccutilscxx = opts.obj util.obj secure.obj init.obj

dll = ccapi_string.obj

srv = ccs_array.obj ccs_cache_collection.obj ccs_callback.obj ccs_ccache.obj \
    ccs_ccache_iterator.obj ccs_client.obj \
    ccs_credentials.obj ccs_credentials_iterator.obj ccs_list.obj ccs_list_internal.obj \
    ccs_lock.obj ccs_lock_state.obj ccs_pipe.obj ccs_server.obj 

srvwin = ccs_os_pipe.obj ccs_reply_c.obj \
    ccs_request_proc.obj ccs_win_pipe.obj

srvwincpp = ccs_os_server.obj ccs_request_s.obj WorkItem.obj WorkQueue.obj
        
linkobjs = $(common) $(commonwin) $(ccutils) $(ccutilscxx) \
    $(srv) $(srvwin) $(srvwincpp)

includes = ccs_reply.h ccs_request.h

# Main program:
server.exe : $(linkobjs) 
#    $(link) $(linkdebug) $(conflags) -MTd -out:ccapiserver.exe $(linkobjs) \
    $(link) $(linkdebug) $(conflags) -out:ccapiserver.exe $(linkobjs) \
        rpcrt4.lib advapi32.lib ws2_32.lib user32.lib


ccs_request.h ccs_request_s.cpp : $(COWIN)\ccs_request.idl $(COWIN)\ccs_request.acf
    midl $(MIDL_OPTIMIZATION) -oldnames -cpp_cmd $(cc) -cpp_opt "-E" -I. -I$(COWIN) -sstub \
        ccs_request_s.cpp $(COWIN)\ccs_request.idl

ccs_reply.h ccs_reply_c.c : $(COWIN)\ccs_reply.idl $(COWIN)\ccs_reply.acf
    midl $(MIDL_OPTIMIZATION) -oldnames -cpp_cmd $(cc) -cpp_opt "-E" -I. -I$(COWIN) \
    $(COWIN)\ccs_reply.idl

$(common) : $(CO)\$*.c
   $(cc) $(cdebug) $(cflags) $(CO)\$*.c

$(commonwin) : $(COWIN)\$*.c
   $(cc) $(cdebug) $(cflags) $(COWIN)\$*.c

$(ccutils) : $(CCUTIL)\$*.c
   $(cc) $(cdebug) $(cflags) $(CCUTIL)\$*.c

$(ccutilscxx) : $(CCUTIL)\$*.cxx
   $(cc) $(cdebug) $(cflags) $(CCUTIL)\$*.cxx

$(srv) : ..\$*.c
   $(cc) $(cdebug) $(cflags) ..\$*.c

$(srvwin) : $*.c $(includes) 
   $(cc) $(cdebug) $(cflags) $*.c

$(srvwincpp) : $*.cpp
   $(cc) $(cdebug) $(cflags) $*.cpp


# Clean up everything
cleanall : clean
    -del *.exe

# Clean up everything but the .EXEs
clean :
    -del *.obj
    -del *.map
    -del ccs_request_s.c
    -del ccs_request_c.c
    -del ccs_request.h
    -del ccs_reply_s.c
    -del ccs_reply_c.c
    -del ccs_reply.h
