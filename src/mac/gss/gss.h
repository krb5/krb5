/**************************************************************************
** 
** gss.h
** 
***************************************************************************/

#define SOCKET int

extern "C" {

#include <string.h>

//#include "gssapi.h"
#include "gssapi_generic.h"

typedef unsigned short u_short;

/*
// gss-misc.c
int send_token(SOCKET s, gss_buffer_t tok);
int recv_token(SOCKET s, gss_buffer_t tok);
void display_status(char *msg, OM_uint32 maj_stat, OM_uint32 min_stat);
static void display_status_1(char *m, OM_uint32 code, int type);

// gss-client.c
int gss (char *host, char *name, char *msg, int port);
int call_server(char *host, u_short port, int dov2, char *service_name, char *msg);
SOCKET connect_to_server(char *host, u_short port);
int client_establish_context(SOCKET s, char *service_name, gss_ctx_id_t *gss_context);*/
}