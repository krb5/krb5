/*+*************************************************************************
** 
** gss.h
** 
** 
***************************************************************************/
#include <windows.h>
#include "winsock.h"
#include <string.h>

#include <gssapi/gssapi.h>
#include <gssapi/gssapi_generic.h>

// gss.c
BOOL PASCAL OpenGssapiDlg(HWND hDlg, WORD message, WORD wParam, LONG lParam);

// gss-misc.c
int send_token(int s, gss_buffer_t tok);
int recv_token(int s, gss_buffer_t tok);
void display_status(char *msg, OM_uint32 maj_stat, OM_uint32 min_stat);
static void display_status_1(char *m, OM_uint32 code, int type);
void OkMsgBox (char *format, ...);
void my_perror (char *msg);

// gss-client.c
int gss (char *host, char *name, char *msg, char *oid, int port);
int call_server(char *host, u_short port, char *service_name, char *oid, char *msg);
int connect_to_server(char *host, u_short port);
int client_establish_context(int s, char *service_name, char *oid, gss_ctx_id_t *gss_context);
