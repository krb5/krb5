/* x25.h - X.25 abstractions */

/*
 * $Header$
 *
 * Contributed by John Pavel, Department of Trade and Industry/National
 * Physical Laboratory in the UK
 *
 *
 * $Log$
 * Revision 1.1  1994/06/10 03:30:13  eichin
 * autoconfed isode for kerberos work
 *
 * Revision 1.1  94/06/10  03:18:37  eichin
 * autoconfed isode for kerberos work
 * 
 * Revision 1.1  1994/05/31 20:38:51  eichin
 * reduced-isode release from /mit/isode/isode-subset/src
 *
 * Revision 8.0  91/07/17  12:34:00  isode
 * Release 7.0
 * 
 * 
 */

/*
 *				  NOTICE
 *
 *    Acquisition, use, and distribution of this module and related
 *    materials are subject to the restrictions of a license agreement.
 *    Consult the Preface in the User's Manual for the full terms of
 *    this agreement.
 *
 */


#ifndef _X25_
#define _X25_

/*
 *
 * #defines for generic addressing & TSEL encoded addresses.
 *
 */

#ifndef _INTERNET_
#include <sys/socket.h>
#endif

#ifdef  SUN_X25
#include <sys/ioctl.h>
#include <sys/param.h>
#include <sys/mbuf.h>
#include <sundev/syncstat.h>
#include <netx25/x25_pk.h>
#include <netx25/x25_ctl.h>
#include <netx25/x25_ioctl.h>
#endif

#ifdef  HPUX_X25
#include <x25/x25.h>
#include <x25/x25addrstr.h>
#include <x25/x25ioctls.h>
#include <x25/x25str.h>
#include <x25/x25codes.h>

#define       MAX_EVENT_SIZE          34
typedef struct x25addrstr     X25_ADDR;
typedef struct x25_userdata     X25_USERDATA;
typedef struct {
      X25_ADDR                addr;
      X25_USERDATA            cudf;
      }                       CONN_DB;
typedef struct x25_cause_diag   X25_CAUSE_DIAG;
typedef struct x25_msg_stat     X25_MSG_STAT;
typedef struct x25_facilities   CCITT_FACILITY_DB;
typedef       struct facility_dB_S {
#define REVCHARGE             0x01
#define       FAST_OFF                0
#define FAST_SELECT           1
#define       FAST_ACPT_CLR           2
#define       FAST_CLR_ONLY           1
#define       CCITT_FAST_OFF          0
#define CCITT_FAST_SELECT     0x80
#define       CCITT_FAST_ACPT_CLR     0x80
#define       CCITT_FAST_CLR_ONLY     0xC0
    u_char    t_01;
       /* Bit 0:       rev-charge allowed                      */
      /* Bit 7:       restricted fast-select (CLR only)       */
      /* Bit 8:       fast-select allowd                      */

    u_char    t_02;
      /* Bits 0-3:    send-thruput                            */
      /* Bits 4-7:    recv-thruput                            */

#define CCITT_CUG             1
#define CCITT_CUG_EXTENDED    3
    u_char    t_03_sel;
    u_short   t_03;
      /* closed user group in 2- or 4-digit BCD               */

#define REQ_CHARGE_INF                1
    u_char    t_04;
      /* Bit 0:       charging information requested          */

#define ACK_EXPECTED  0x01
#define NACK_EXPECTED 0x02
    u_char    t_07;
      /* Bit 0:       send ACK                                */
      /* Bit 1:       send NACK                               */

    u_char    t_08;
      /* called line address modified notification            */
define CCITT_OUTCUG_EXTENDED 3
    u_char    t_09_sel;
    u_short   t_09;
      /* closed user group in 2- or 4-digit BCD               */

    u_char    t_41_sel;
    u_short   t_41;
      /* bilateral closed user group in 4-digit BCD           */

    u_char    t_42 [2];
      /* Byte 0:      recv-pcktsize (log2)                    */
      /* Byte 1:      send-pcktsize (log2)                    */

    u_char    t_43 [2];
      /* Byte 0:      recv-windowsize                         */
      /* Byte 1:      send-windowsize                         */

#define CCITT_RPOA            1
    u_char    t_44_sel;
    u_short   t_44;
      /* RPOA transit number                                  */

    u_char    t_49_sel;
    u_short   t_49;
      /* Transit delay selection and indication               */

    u_char    *t_c1;
      /* call duration charge-information                     */
      /* Byte 0:      length of fac. parm. field              */
    u_char    *t_c2;
      /* segment count charge-information                     */
      /* Byte 0:      length of fac. parm. field              */

    u_char    *t_c3;
      /* call deflection/restriction notification             */
      /* Byte 0:      length of fac. parm. field              */
      /* Byte 1:      deflection reason                       */

    u_char    *t_c4;
      /* RPOA extended format                                 */
      /* Byte 0:      length of fac. parm. field              */

    u_char    *t_c5;
      /* monetary unit charge-information                     */
      /* Byte 0:      length of fac. parm. field              */

    u_char    *t_c6;
      /* NUI selection                                        */
      /* Byte 0:      length of fac. parm. field              */

    u_char    *t_d1;
      /* CALL deflection                                      */
      /* Byte 0:      length of fac. parm. field              */
      /* Byte 1:      deflection reason from remote DTE       */
      /* Byte 2:      length of alt. DTE (in digits)          */
} FACILITY_DB;
#endif


#include <sys/protosw.h>
#include <sys/domain.h>
#include <sys/socketvar.h>
#include <sys/errno.h>
#include <net/if.h>

#ifdef  CAMTEC
#include <cci.h>
typedef struct  ccontrolp CONN_DB;
#undef  NTPUV
#define NTPUV   2               /* CAMTEC allows only 2 iov's per read/write */
#endif

#ifdef  CAMTEC_CCL
#include <sys/ioctl.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <netccl/ccl.h>

typedef struct ccliovec CONN_DB;
#endif


#ifdef UBC_X25
#include <netccitt/x25_sockaddr.h>
#ifdef BSD44
#include <sys/ioctl.h>
#endif

#define         X25_PACKETSIZE  128

typedef struct x25_sockaddr CONN_DB;
#endif


#ifdef	ULTRIX_X25
#include <netx25/x25.h>
#include <stdio.h>
#include <sys/time.h>

typedef struct NSAPaddr CONN_DB; /* 
				 * address translation is delayed until
				 * connect()/accept() time and returns
				 * as fields in a packed structure. calls
				 * to an X25Encode() X25Decode() routine
				 * unpacks this directly into the ISODE
				 * NSAPaddr buffer. not as simple as
				 * some but DEC like to be different (sigh)
				 */

#define select_x25_socket    selsocket
#define read_x25_socket      read
#define write_x25_socket     write

#endif	/* ULTRIX_X25 */
/*  */

#ifdef SUN_X25
#define close_x25_socket     close
#define select_x25_socket    selsocket
#define read_x25_socket      read
#define write_x25_socket     write
#endif

#ifdef HPUX_X25
#define REST_TYPE 2
#define select_x25_socket    selsocket
#define read_x25_socket      read
#define write_x25_socket     write
#endif

#if     defined(UBC_X25) || defined(CAMTEC_CCL) 
#define close_x25_socket     close
#define select_x25_socket    selsocket
#endif

#ifndef	RECV_DIAG
#define RECV_DIAG 0
#define DIAG_TYPE 1
#define WAIT_CONFIRMATION 2
#endif

int     start_x25_client ();
int     start_x25_server ();
int     join_x25_client ();
int     join_x25_server ();
int     read_x25_socket ();
int     write_x25_socket ();
int     close_x25_socket ();
int     select_x25_socket ();

struct NSAPaddr *if2gen();
CONN_DB *gen2if();


#define ADDR_LOCAL      0
#define ADDR_REMOTE     1
#define ADDR_LISTEN     2
#define SEPARATOR ':'


#define MAXNSDU 2048			/* must be equal to largest TP0 TPDU */
#endif
