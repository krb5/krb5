/*
 *----------------------------------------------------------------
 *
 *  $Source$
 *  $Revision$
 *  $Date$
 *  $State$
 *  $Author$ Jason Sachs (nosaj)
 *  $Locker$
 *
 *  $Log$
 *  Revision 1.2  1997/04/29 10:45:02  tytso
 *  Remove #include of "mitcpyrt.h" (since it's of dubious legal value, and
 *  the file doesn't exist.)
 *
 *  Revision 1.1  1997/04/17 15:25:52  tytso
 *  Add MIT's version server include files and libraries.
 *
 * Revision 1.3  92/08/27  10:44:51  pbh
 * alpha 0.2a check in
 * rebuilt manually
 * 
 * Revision 0.1  92/08/25  10:00:20  pbh
 * alpha 0.1a
 */



/* vs.h -- defines for the Version Server checking routines. */

/* jms 6/3/92 */

#ifndef VS_HEADER_STUFF
#define VS_HEADER_STUFF

#include "v.h"
#include <stdlib.h>

typedef unsigned char VS_Status;
typedef unsigned long VS_Request; /* For compatibility reasons */

#if defined(WINDOWS) || defined(MEWEL)
  #ifdef VS_INCWINDOWS
    #include <windows.h>
  #endif /* should we include windows.h here? */
#else
  #ifndef FAR /* il 7/25/95 */
    #define FAR
    /* no need for that here */
  #endif

  #ifndef BOOL /* il 7/25/95 */
    #define BOOL int
  #endif
    
  #ifndef NULL
    #define NULL 0
  #endif /* Null */

#endif

/* patch for nt.  il 7/24/95 -- adding nt */
#include "vs_nt.h"

typedef struct v_req_info VS_ReqInfo, *VS_ReqInfoPtr;
#define VS_NAT_ReqInfoPtr VS_ReqInfo *

#if defined(MEWEL) || defined(WINDOWS)
  #if defined(WIN32) /* il 7/27/95 -- added nt */
    #define RequestAlloc (VS_Request) LocalAlloc
    #define RequestLock(request) (VS_ReqInfoPtr) LocalLock((LOCALHANDLE)(request))
    #define RequestFree(request) LocalFree((LOCALHANDLE)(request))
    #define RequestUnlock(request) LocalUnlock((LOCALHANDLE)(request))
  #else
    #define RequestAlloc (VS_Request) LocalAlloc
    #define RequestLock(request) (VS_ReqInfoPtr) LocalLock((LOCALHANDLE)(LOWORD(request)))
    #define RequestFree(request) LocalFree((LOCALHANDLE)(LOWORD(request)))
    #define RequestUnlock(request) LocalUnlock((LOCALHANDLE)(LOWORD(request)))
  #endif
#else                            
    #define RequestAlloc(flags,size) (VS_Request) malloc(size)
    #define RequestLock (char *)
    #define RequestFree(request) free((char *) request)
    #define RequestUnlock(request) /* nothin' */
#endif /* jms 08/13/93 */

/* status codes */

#define V_E_SELECT                              255
#define V_E_TIMEOUT                             254
#define V_E_SELECT_STRANGEFD                    253
#define V_E_RECVFROM                            252
#define V_E_UNKNOWN                             251
#define V_E_BAD_OP_CODE                         250
#define V_E_HOSTNOTFOUND                        249
#define V_E_SOCKET                              248
#define V_E_BIND                                247
#define V_E_SENDTO                              246
#define V_E_DLLNOTFOUND                         245
#define V_E_NOMEMORY                            244
#define V_E_CANCEL                              243

#define VSR_OK                                    0

/* classifications of errors */

#define V_C_NOERROR                             0
#define V_C_TRY_AGAIN                           1
#define V_C_DEFINITE                            2
#define V_C_FAIL                                3

extern VS_Status _far _cdecl err_classify(VS_Status error);
#if defined(MEWEL) || defined(WINDOWS)
/* jms 2/16/93 */
extern BOOL _far _cdecl v_complain(VS_Status error, LPSTR inifilename);
#endif

#define V_TRY_AGAIN(status) (err_classify(status)==V_C_TRY_AGAIN)
#define V_FAIL(status)     (err_classify(status)==V_C_FAIL)
#define V_DEFINITE(status)  (err_classify(status)==V_C_DEFINITE)

#define V_STATUS(vinfo) ((VS_Status)*((vinfo).status))
 /* grumble... this abstraction should be in v.h... */

/* the main routines */

#if defined(MEWEL) || defined(WINDOWS)
#ifndef NOCODECOVER
extern VS_Request _far _cdecl VSFormRequest(char FAR *name, char FAR *version,
                char FAR *ininame, char FAR *codecover, HWND hWnd,
                int HowToCheck);
#else
extern VS_Request _far _cdecl VSFormRequest(char FAR *name, char FAR *version,
                char FAR *ininame, HWND hWnd,
                int HowToCheck);
#endif

#else
extern VS_Request _far _cdecl VSFormRequest(char *name, char *version, int HowToCheck);
#endif

extern VS_Status _far _cdecl VSProcessRequest(VS_Request request);
#if defined(WINDOWS) || defined(MEWEL)
extern void _far _cdecl WinVSReportRequest(VS_Request request, HWND hWnd, char FAR *title);
extern void _far _cdecl TTChangeRegistration(char FAR *ininame, HWND hWnd, LPSTR DlgBoxName);
extern BOOL _far _cdecl v_complain(VS_Status error, LPSTR inifilename);
#else
extern void _far _cdecl TTYVSReportRequest(VS_Request request);
#endif
extern void _far _cdecl VSDestroyRequest(VS_Request request);
extern void _far _cdecl PickVersionServer(char FAR *name);
#define HNAMESIZE 40 /* max. chars in the VS server name. */
#define HSPSIZE 2    /* no. chars in send packets option */

#ifndef VS_INTERNAL
extern VS_Request _far _cdecl MakeRequest( VS_Status status );
extern VS_Status _far _cdecl ReqStatus ( VS_Request hrequest );
#endif

#endif /* VS_HEADER_STUFF */

/*
 * The application should call the first two routines, and optionally
 * the third, in order. It should only quit if CheckVS returns V_REQUIRED.
 * If this is a Windows/Mewel program, a call to PostQuitMessage(0) is the
 * best way to do things, unless some cleanup needs to be done... but the
 * Version Server checking should be done as early as possible so this
 * shouldn't be a problem.
 */

#if 0
/* here's an example: */
  VS_Request request;
  VS_Status status;

  request = VSFormRequest(APPLICATION_NAME, APP_VER, "1st alpha");
  status = VSProcessRequest(request);
  WinVSReportRequest(request, hMainWin, "Version Server Status Report");
  if (status == V_REQUIRED)
    PostQuitMessage(0); /* This is an outdated version of TechInfo! */
  VSDestroyRequest(request);
#endif
