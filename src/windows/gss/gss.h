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
INT_PTR CALLBACK OpenGssapiDlg(	HWND hDlg,	UINT message,	WPARAM wParam,	LPARAM lParam);

// gss-misc.c
int send_token(int s, int flags, gss_buffer_t tok);
int recv_token(int s, int *flags, gss_buffer_t tok);
void free_token(gss_buffer_t tok);
void display_status(char *msg, OM_uint32 maj_stat, OM_uint32 min_stat);
static void display_status_1(char *m, OM_uint32 code, int type);
void OkMsgBox (char *format, ...);
void my_perror (char *msg);

// gss-client.c
int
gss (char *server_host, char *service_name, char *mechanism, char *msg, int port,
     int verbose, int delegate, int mutual, int replay, int sequence,
     int v1_format, int auth_flag, int wrap_flag,
     int encrypt_flag, int mic_flag, int ccount, int mcount, char * ccache);
int call_server(char *host, u_short port, gss_OID oid, char *service_name,
                OM_uint32 deleg_flag, int auth_flag,
		        int wrap_flag, int encrypt_flag, int mic_flag, int v1_format,
                char *msg, int use_file, int mcount);
int connect_to_server(char *host, u_short port);
int client_establish_context(int s, char *service_name, OM_uint32 deleg_flag,
                             int auth_flag, int v1_format, gss_OID oid,
                             gss_ctx_id_t *gss_context, OM_uint32 *ret_flags);


extern int verbose;
#define printf  gss_printf
