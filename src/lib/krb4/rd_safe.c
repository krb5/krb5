/*
 * rd_safe.c
 *
 * CopKRB4_32right 1986, 1987, 1988 by the Massachusetts Institute
 * of Technology.
 *
 * For copying and distribution information, please see the file
 * <mit-copyright.h>.
 *
 * This routine dissects a a Kerberos 'safe msg', checking its
 * integrity, and returning a pointer to the application data
 * contained and its length.
 *
 * Returns 0 (RD_AP_OK) for success or an error code (RD_AP_...)
 *
 * Steve Miller    Project Athena  MIT/DEC
 */

#include "mit-copyright.h"

/* system include files */
#include <stdio.h>
#include <string.h>

/* application include files */
#define	DEFINE_SOCKADDR		/* Ask for sockets declarations from krb.h. */
#include "krb.h"
#include "prot.h"
#include "des.h"
#include "lsb_addr_cmp.h"

extern int krb_debug;

/*
 * krb_rd_safe() checks the integrity of an AUTH_MSG_SAFE message.
 * Given the message received, "in", the length of that message,
 * "in_length", the "key" to compute the checksum with, and the
 * network addresses of the "sender" and "receiver" of the message,
 * krb_rd_safe() returns RD_AP_OK if message is okay, otherwise
 * some error code.
 *
 * The message data retrieved from "in" is returned in the structure
 * "m_data".  The pointer to the application data (m_data->app_data)
 * refers back to the appropriate place in "in".
 *
 * See the file "mk_safe.c" for the format of the AUTH_MSG_SAFE
 * message.  The structure containing the extracted message
 * information, MSG_DAT, is defined in "krb.h".
 */

KRB5_DLLIMP long KRB5_CALLCONV
krb_rd_safe(in,in_length,key,sender,receiver,m_data)
    u_char FAR *in;			/* pointer to the msg received */
    unsigned KRB4_32 in_length;		/* length of "in" msg */
    C_Block FAR key;			/* encryption key for seed and ivec */
    struct sockaddr_in FAR *sender;	/* sender's address */
    struct sockaddr_in FAR *receiver;	/* receiver's address -- me */
    MSG_DAT FAR *m_data;		/* where to put message information */
{
    unsigned KRB4_32 calc_cksum[4];
    unsigned KRB4_32 big_cksum[4];
    int swap_bytes;

    u_char     *p,*q;
    unsigned KRB4_32  src_addr; /* Can't send structs since no
				   * guarantees on size */
    unsigned KRB4_32 t_local;	/* Local time in our machine */
    KRB4_32 delta_t;		/* Difference between timestamps */

    /* Be very conservative */
    if (sizeof(src_addr) != sizeof(struct in_addr)) {
#ifdef DEBUG
        fprintf(stderr,"\n\
krb_rd_safe protocol err sizeof(u_long) != sizeof(struct in_addr)");
#endif
        return RD_AP_VERSION;
    }

    p = in;                     /* beginning of message */
    swap_bytes = 0;

    if (*p++ != KRB_PROT_VERSION)       return RD_AP_VERSION;
    if (((*p) & ~1) != AUTH_MSG_SAFE) return RD_AP_MSG_TYPE;
    if ((*p++ & 1) != HOST_BYTE_ORDER) swap_bytes++;

    q = p;                      /* mark start of cksum stuff */

    /* safely get length */
    memcpy((char *)&(m_data->app_length), (char *)p, 
	   sizeof(m_data->app_length));
    if (swap_bytes) m_data->app_length = krb4_swab32(m_data->app_length);
    p += sizeof(m_data->app_length); /* skip over */

    if (m_data->app_length + sizeof(in_length)
        + sizeof(m_data->time_sec) + sizeof(m_data->time_5ms)
        + sizeof(big_cksum) + sizeof(src_addr)
        + VERSION_SZ + MSG_TYPE_SZ > in_length)
        return(RD_AP_MODIFIED);

    m_data->app_data = p;       /* we're now at the application data */

    /* skip app data */
    p += m_data->app_length;

    /* safely get time_5ms */
    memcpy((char *)&(m_data->time_5ms), (char *)p, 
	   sizeof(m_data->time_5ms));

    /* don't need to swap-- one byte for now */
    p += sizeof(m_data->time_5ms);

    /* safely get src address */
    memcpy((char *)&src_addr, (char *)p, sizeof(src_addr));

    /* don't swap, net order always */
    p += sizeof(src_addr);

    if (!krb_ignore_ip_address &&
	src_addr != (unsigned KRB4_32) sender->sin_addr.s_addr)
        return RD_AP_MODIFIED;

    /* safely get time_sec */
    memcpy((char *)&(m_data->time_sec), (char *)p, 
          sizeof(m_data->time_sec));
    if (swap_bytes)
        m_data->time_sec = krb4_swab32(m_data->time_sec);
    p += sizeof(m_data->time_sec);

    /* check direction bit is the sign bit */
    /* For compatibility with broken old code, compares are done in VAX 
       byte order (LSBFIRST) */ 
    /* However, if we don't have good ip addresses anyhow, just clear
       the bit. This makes it harder to detect replay of sent packets
       back to the receiver, but most higher level protocols can deal
       with that more directly. */
    if (krb_ignore_ip_address) {
        if (m_data->time_sec <0)
            m_data->time_sec = -m_data->time_sec;
    } else if (lsb_net_ulong_less(sender->sin_addr.s_addr,
			   receiver->sin_addr.s_addr)==-1) 
	/* src < recv */ 
	m_data->time_sec =  - m_data->time_sec; 
    else if (lsb_net_ulong_less(sender->sin_addr.s_addr, 
				receiver->sin_addr.s_addr)==0) 
	if (lsb_net_ushort_less(sender->sin_port,receiver->sin_port)==-1)
	    /* src < recv */
	    m_data->time_sec =  - m_data->time_sec; 

    /*
     * All that for one tiny bit!  Heaven help those that talk to
     * themselves.
     */

    /* check the time integrity of the msg */
    t_local = TIME_GMT_UNIXSEC;
    delta_t = t_local - m_data->time_sec;
    if (delta_t < 0) delta_t = -delta_t;  /* Absolute value of difference */
    if (delta_t > CLOCK_SKEW) {
        return(RD_AP_TIME);		/* XXX should probably be better
					   code */
    }

    /*
     * caller must check timestamps for proper order and replays, since
     * server might have multiple clients each with its own timestamps
     * and we don't assume tightly synchronized clocks.
     */

    memcpy((char *)big_cksum, (char *)p, sizeof(big_cksum));
    if (swap_bytes) {
      /* swap_u_16(big_cksum); */
      unsigned KRB4_32 *bb;
      bb = (unsigned KRB4_32*)big_cksum;
      bb[0] = krb4_swab32(bb[0]);  bb[1] = krb4_swab32(bb[1]);
      bb[2] = krb4_swab32(bb[2]);  bb[3] = krb4_swab32(bb[3]);
    }

#ifdef NOENCRYPTION
    memset(calc_cksum, 0, sizeof(calc_cksum));
#else /* Do encryption */
    /* calculate the checksum of the length, timestamps, and
     * input data, on the sending byte order !! */
    quad_cksum(q,calc_cksum,p-q,2,(C_Block *)key);
#endif /* NOENCRYPTION */

    DEB (("\n0: calc %l big %lx\n1: calc %lx big %lx\n2: calc %lx big %lx\n3: calc %lx big %lx\n",
               calc_cksum[0], big_cksum[0],
               calc_cksum[1], big_cksum[1],
               calc_cksum[2], big_cksum[2],
               calc_cksum[3], big_cksum[3]));
    if (memcmp((char *)big_cksum,(char *)calc_cksum,sizeof(big_cksum)))
        return(RD_AP_MODIFIED);

    return(RD_AP_OK);           /* OK == 0 */
}
