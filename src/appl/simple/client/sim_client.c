/*
 * $Source$
 * $Author$
 *
 * Copyright 1989,1991 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
 *
 * Simple UDP-based sample client program.  For demonstration.
 * This program performs no useful function.
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_sim_client_c[] =
"$Id$";
#endif	/* !lint & !SABER */


#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <stdio.h>
#include <ctype.h>

#include <krb5/krb5.h>
#include <krb5/ext-proto.h>
#include <krb5/los-proto.h>
#include <com_err.h>

#include "simple.h"

#define MSG "hi there!"			/* message text */

#define PROGNAME argv[0]
#define HOST argv[1]

void
main(argc, argv)
int argc;
char *argv[];
{
    int sock, i;
    int flags = 0;			/* flags for sendto() */
    struct servent *serv;
    struct hostent *host;
    char *cp;
    char full_hname[256];		/* XXX magic number */
    struct sockaddr_in s_sock;		/* server address */
    struct sockaddr_in c_sock;		/* client address */

    krb5_error_code retval;
    char *c_realm;			/* local Kerberos realm */
    char **s_realms;			/* server's Kerberos realm(s) */
    krb5_data scontents[3], *server[4];	/* a krb5_principal is really a
					   krb5_data *[] */
    krb5_data packet, inbuf;
    krb5_checksum send_cksum;
    krb5_ccache ccdef;
    krb5_creds creds;
    krb5_address local_addr, foreign_addr, *portlocal_addr;
    krb5_rcache rcache;
    extern krb5_deltat krb5_clockskew;

    if (argc != 2 && argc != 3) {
	fprintf(stderr, "usage: %s <hostname> [message]\n",PROGNAME);
	exit(1);
    }
    
    krb5_init_ets();

    if (!valid_cksumtype(CKSUMTYPE_CRC32)) {
	com_err(PROGNAME, KRB5_PROG_SUMTYPE_NOSUPP, "while using CRC-32");
	exit(1);
    }

    /* Look up service */
    if ((serv = getservbyname(SERVICE, "udp")) == NULL) {
	fprintf(stderr, "service unknown: %s/udp\n", SERVICE);
	exit(1);
    }

    /* Look up server host */
    if ((host = gethostbyname(HOST)) == (struct hostent *) 0) {
	fprintf(stderr, "%s: unknown host\n", HOST);
	exit(1);
    }
    strncpy(full_hname, host->h_name, sizeof(full_hname)-1);

    /* lower-case to get name for "instance" part of service name */
    for (cp = full_hname; *cp; cp++)
        if (isupper(*cp))
            *cp = tolower(*cp);

    /* Set server's address */
    (void) memset((char *)&s_sock, 0, sizeof(s_sock));

    memcpy((char *)&s_sock.sin_addr, host->h_addr, host->h_length);
#ifdef DEBUG
    printf("s_sock.sin_addr is %s\n", inet_ntoa(s_sock.sin_addr));
#endif
    s_sock.sin_family = AF_INET;
    s_sock.sin_port = serv->s_port;

    foreign_addr.addrtype = ADDRTYPE_INET;
    foreign_addr.length = sizeof(s_sock.sin_addr);
    foreign_addr.contents = (krb5_octet *)&s_sock.sin_addr;

    /* Open a socket */
    if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
	com_err(PROGNAME, errno, "opening datagram socket");
	exit(1);
    }

    memset((char *)&c_sock, 0, sizeof(c_sock));
    c_sock.sin_family = AF_INET;

    /* Bind it to set the address; kernel will fill in port # */
    if (bind(sock, (struct sockaddr *)&c_sock, sizeof(c_sock)) < 0) {
	com_err(PROGNAME, errno, "while binding datagram socket");
	exit(1);
    }
	
    if (retval = krb5_get_default_realm(&c_realm)) {
	com_err(PROGNAME, retval, "while retrieving local realm");
	exit(1);
    }
    printf("Local Kerberos realm is %s\n", c_realm);

    /* Get Kerberos realm of host */
    if (retval = krb5_get_host_realm(HOST, &s_realms)) {
	com_err(PROGNAME, retval, "while getting realm for '%s'", HOST);
	exit(1);
    }
#ifdef DEBUG
    printf("Kerberos realm #1 of %s is %s\n", HOST, s_realms[0]);
#endif

    /* PREPARE KRB_AP_REQ MESSAGE */

    /* compute checksum, using CRC-32 */
    if (!(send_cksum.contents = (krb5_octet *)
	  malloc(krb5_checksum_size(CKSUMTYPE_CRC32)))) {
	com_err(PROGNAME, ENOMEM, "while allocating checksum");
	exit(1);
    }

    /* choose some random stuff to compute checksum from */
    if (retval = krb5_calculate_checksum(CKSUMTYPE_CRC32,
					 HOST,
					 strlen(HOST),
					 0,
					 0, /* if length is 0, crc-32 doesn't
					       use the seed */
					 &send_cksum)) {
	com_err(argv[0], retval, "while computing checksum");
	exit(1);
    }

    /* Get credentials for server, create krb_mk_req message */

    if (retval = krb5_cc_default(&ccdef)) {
	com_err(PROGNAME, retval, "while getting default ccache");
	exit(1);
    }

    /* compose the server name. [0] == realm,
       				[1] == service name (by convention),
				[2] == FULL host name (by convention)
				[3] == null ptr */

    scontents[0].length = strlen(s_realms[0]);
    scontents[0].data = s_realms[0];
    scontents[1].length = strlen(SERVICE);
    scontents[1].data = SERVICE;
    scontents[2].length = strlen(full_hname);
    scontents[2].data = full_hname;
    server[0] = &scontents[0];
    server[1] = &scontents[1];
    server[2] = &scontents[2];
    server[3] = 0;

    if (retval = krb5_mk_req(server,
			     0,		/* use default options */
			     &send_cksum,
			     ccdef,
			     &packet)) {
	com_err(PROGNAME, retval, "while preparing AP_REQ");
	exit(1);
    }
    printf("Got credentials for %s.\n", SERVICE);

    /* Send authentication info to server */
    i = sendto(sock, (char *)packet.data, packet.length, flags,
	       (struct sockaddr *)&s_sock, sizeof(s_sock));
    if (i < 0)
	com_err(PROGNAME, errno, "while sending KRB_AP_REQ message");
    printf("Sent authentication data: %d bytes\n", i);

    xfree(packet.data);
    /* PREPARE KRB_SAFE MESSAGE */

    /* Get my address */
    memset((char *) &c_sock, 0, sizeof(c_sock));
    i = sizeof(c_sock);
    if (getsockname(sock, (struct sockaddr *)&c_sock, &i) < 0) {
	com_err(PROGNAME, errno, "while getting socket name");
	exit(1);
    }
    local_addr.addrtype = ADDRTYPE_INET;
    local_addr.length = sizeof(c_sock.sin_addr);
    local_addr.contents = (krb5_octet *)&c_sock.sin_addr;

    if (retval = krb5_gen_portaddr(&local_addr,
				   (krb5_pointer) &c_sock.sin_port,
				   &portlocal_addr)) {
	com_err(PROGNAME, retval, "while generating port address");
	exit(1);
    }
    
    if (retval = krb5_gen_replay_name(portlocal_addr, "_sim_clt",
				      &cp)) {
	com_err(PROGNAME, retval, "while generating replay cache name");
	exit(1);
    }
    if (!(rcache = (krb5_rcache)malloc(sizeof(*rcache)))) {
	com_err(PROGNAME, ENOMEM, "while allocating replay cache");
	exit(1);
    }
    if (retval = krb5_rc_resolve_type(&rcache, krb5_rc_default_type())) {
	xfree(rcache);
	com_err(PROGNAME, retval, "while resolving replay cache type");
	exit(1);
    }
    if (retval = krb5_rc_resolve(rcache, cp)) {
	xfree(rcache);
	com_err(PROGNAME, retval, "while resolving replay cache type");
	exit(1);
    }
    if ((retval = krb5_rc_recover(rcache)) &&
	(retval = krb5_rc_initialize(rcache, krb5_clockskew))) {
	com_err(PROGNAME, retval, "while initializing replay cache '%s:%s'",
		rcache->ops->type,
		krb5_rc_get_name(rcache));
	exit(1);
    }

    /* Get session key & creds */
    memset((char *)&creds, 0, sizeof(creds));
    creds.server = server;
    if (retval = krb5_cc_get_principal(ccdef, &creds.client)) {
	com_err(PROGNAME, retval, "while getting my principal name");
	exit(1);
    }

    if (retval = krb5_get_credentials(0, /* no flags */
				      ccdef,
				      &creds)) {
	com_err(PROGNAME, retval, "while fetching credentials");
	exit(1);
    }

    /* Make the safe message */
    inbuf.data = argc == 3 ? argv[2] : MSG;
    inbuf.length = strlen (inbuf.data);

    if (retval = krb5_mk_safe(&inbuf,
			      CKSUMTYPE_RSA_MD4_DES,
			      &creds.keyblock, 
			      portlocal_addr, 
			      &foreign_addr,
			      0, 0,	/* no seq number or special flags */
			      rcache,
			      &packet)) {
	com_err(PROGNAME, retval, "while making KRB_SAFE message");
	exit(1);
    }

    /* Send it */
    i = sendto(sock, (char *)packet.data, packet.length, flags,
	       (struct sockaddr *)&s_sock, sizeof(s_sock));
    if (i < 0)
	com_err(PROGNAME, errno, "while sending SAFE message");
    printf("Sent checksummed message: %d bytes\n", i);
    if (i < 0)
	perror("sending safe message");

    xfree(packet.data);
    /* PREPARE KRB_PRIV MESSAGE */


    /* Make the encrypted message */
    if (retval = krb5_mk_priv(&inbuf,
			      ETYPE_DES_CBC_CRC,
			      &creds.keyblock, 
			      portlocal_addr, 
			      &foreign_addr,
			      0, 0,	/* no seq number or special flags */
			      rcache,
			      0,	/* default ivec/don't care */
			      &packet)) {
	com_err(PROGNAME, retval, "while making KRB_PRIV message");
	exit(1);
    }

    /* Send it */
    i = sendto(sock, (char *)packet.data, packet.length, flags,
	       (struct sockaddr *)&s_sock, sizeof(s_sock));
    if (i < 0)
	com_err(PROGNAME, errno, "while sending PRIV message");
    printf("Sent encrypted message: %d bytes\n", i);
    exit(0);
}
