/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* lib/krb5/os/os-proto.h */
/*
 * Copyright 1990,1991,2009 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * Export of this software from the United States of America may
 *   require a specific license from the United States Government.
 *   It is the responsibility of any person or organization contemplating
 *   export to obtain such a license before exporting.
 *
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of M.I.T. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 */

/*
 *
 * LIBOS internal function prototypes.
 */

#ifndef KRB5_LIBOS_INT_PROTO__
#define KRB5_LIBOS_INT_PROTO__

#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif

#include <krb5/locate_plugin.h>

/* A single server hostname or address. */
struct server_entry {
    char *hostname;             /* NULL -> use addrlen/addr instead */
    int port;                   /* Used only if hostname set */
    int socktype;               /* May be 0 for UDP/TCP if hostname set */
    int family;                 /* May be 0 (aka AF_UNSPEC) if hostname set */
    size_t addrlen;
    struct sockaddr_storage addr;
};

/* A list of server hostnames/addresses. */
struct serverlist {
    struct server_entry *servers;
    size_t nservers;
};
#define SERVERLIST_INIT { NULL, 0 }

krb5_error_code k5_locate_server(krb5_context, const krb5_data *realm,
                                 struct serverlist *,
                                 enum locate_service_type svc, int socktype);

krb5_error_code k5_locate_kdc(krb5_context context, const krb5_data *realm,
                              struct serverlist *serverlist, int get_masters,
                              int socktype);

void k5_free_serverlist(struct serverlist *);

#ifdef HAVE_NETINET_IN_H
krb5_error_code krb5_unpack_full_ipaddr(krb5_context,
                                        const krb5_address *,
                                        krb5_int32 *,
                                        krb5_int16 *);

krb5_error_code krb5_make_full_ipaddr(krb5_context,
                                      krb5_int32,
                                      int,   /* unsigned short promotes to signed int */
                                      krb5_address **);

#endif /* HAVE_NETINET_IN_H */

krb5_error_code krb5_try_realm_txt_rr(const char *, const char *,
                                      char **realm);

void krb5int_debug_fprint (const char *fmt, ...);

int _krb5_use_dns_realm (krb5_context);
int _krb5_use_dns_kdc (krb5_context);
int _krb5_conf_boolean (const char *);

krb5_error_code k5_sendto(krb5_context context, const krb5_data *message,
                          const struct serverlist *addrs,
                          int socktype1, int socktype2,
                          struct sendto_callback_info *callback_info,
                          krb5_data *reply, struct sockaddr *remoteaddr,
                          socklen_t *remoteaddrlen, int *server_used,
                          int (*msg_handler)(krb5_context, const krb5_data *,
                                             void *),
                          void *msg_handler_data);

krb5_error_code krb5int_get_fq_local_hostname(char *, size_t);

/* The io vector is *not* const here, unlike writev()!  */
int krb5int_net_writev (krb5_context, int, sg_buf *, int);

int k5_getcurtime(struct timeval *tvp);

krb5_error_code k5_expand_path_tokens(krb5_context context,
                                      const char *path_in, char **path_out);
krb5_error_code k5_expand_path_tokens_extra(krb5_context context,
                                            const char *path_in,
                                            char **path_out, ...);

#include "k5-thread.h"
extern k5_mutex_t krb5int_us_time_mutex;

extern unsigned int krb5_max_skdc_timeout;
extern unsigned int krb5_skdc_timeout_shift;
extern unsigned int krb5_skdc_timeout_1;
extern unsigned int krb5_max_dgram_size;


#endif /* KRB5_LIBOS_INT_PROTO__ */
