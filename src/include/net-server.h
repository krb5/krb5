/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 * include/net-server.h
 *
 * Copyright (C) 2010 by the Massachusetts Institute of Technology.
 * All rights reserved.
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
 *
 *
 * Declarations for "API" of network listener/dispatcher in libapputils.
 */

#ifndef NET_SERVER_H
#define NET_SERVER_H

typedef struct _krb5_fulladdr {
    krb5_address *      address;
    krb5_ui_4           port;
} krb5_fulladdr;

/* exported from network.c */
extern volatile int signal_requests_exit, signal_requests_reset;
void init_addr(krb5_fulladdr *, struct sockaddr *);
krb5_error_code add_udp_port(int port);
krb5_error_code add_tcp_port(int port);
krb5_error_code add_rpc_service(int port, u_long prognum, u_long versnum,
                                void (*dispatch)());
krb5_error_code setup_network(void *handle, const char *prog, int no_reconfig);
krb5_error_code listen_and_process(void *handle, const char *prog,
                                   void (*reset)(void));
void closedown_network(void);

/* to be supplied by the server application */

/*
 * Two routines for processing an incoming message and getting a
 * result to send back.
 *
 * The first, dispatch(), is for normal processing of a request.  The
 * second, make_toolong_error(), is obviously for generating an error
 * to send back when the incoming message is bigger than
 * listen_and_process can accept.
 */
krb5_error_code dispatch (void *handle,
                          struct sockaddr *local_addr,
                          const krb5_fulladdr *remote_addr,
                          krb5_data *request,
                          krb5_data **response,
                          int is_tcp);
krb5_error_code make_toolong_error (void *handle, krb5_data **);

/*
 * Contexts are needed in lots of places.  Opaque application-provided
 * handles are passed around in lots of place, but contexts are not.
 * For now, we'll require that the application provide us an easy way
 * to get at a context; eventually it should probably be explicity.
 */
krb5_context get_context(void *handle);

#endif /* NET_SERVER_H */
