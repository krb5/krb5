/*
 * mac_time.c
 * (Originally time_stuff.c)
 *
 * Copyright 1989 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <mit-copyright.h>.
 *
 * Macintosh ooperating system interface for Kerberos.
 */

#include "mit-copyright.h"
#include "krb.h"
#include "des.h"
#include "AddressXlation.h"	/* for ip_addr */
#include <time.h>
#include <sys/time.h>

#include <script.h>			/* Defines MachineLocation, used by getTimeZoneOffset */
#include <ToolUtils.h>		/* Defines BitTst(), called by getTimeZoneOffset() */
#include <OSUtils.h>		/* Defines GetDateTime */

/* Mac Cincludes */
#include <string.h>
#include <stddef.h>


  /*******************************
  The Unix epoch is 1/1/70, the Mac epoch is 1/1/04.

  70 - 4 = 66 year differential

  Thus the offset is:

  (66 yrs) * (365 days/yr) * (24 hours/day) * (60 mins/hour) * (60 secs/min)
  plus
  (17 leap days) * (24 hours/day) * (60 mins/hour) * (60 secs/min)

  Don't forget the offset from GMT.
  *******************************/


/* returns the offset in hours between the mac local time and the GMT  */

unsigned long
getTimeZoneOffset()
{
	MachineLocation		macLocation;
	long			gmtDelta;

	macLocation.gmtFlags.gmtDelta=0L;
	ReadLocation(&macLocation); 
	gmtDelta=macLocation.gmtFlags.gmtDelta & 0x00FFFFFF;
	if (BitTst((void *)&gmtDelta,23L))	gmtDelta |= 0xFF000000;
	gmtDelta /= 3600L;
	return(gmtDelta);
}


/* Returns the GMT in seconds using the Unix epoch, ie. Net time */

static unsigned long
gettimeofdaynet_no_offset()
{
	time_t the_time;
	
	GetDateTime (&the_time);
	the_time = the_time - 
		((66 * 365 * 24 * 60 * 60) + 
		      (17 *  24 * 60 * 60) +
           (getTimeZoneOffset() * 60 * 60));
	return the_time;
}



int	
gettimeofdaynet (struct timeval *tp, struct timezone *tz)
{ 
	tp->tv_sec = gettimeofdaynet_no_offset();
	return 0;
}


#if 0

int	
gettimeofdaynet (struct timeval *tp, struct timezone *tz)
{
	int result;
	
	if (!net_got_offset)
		result = get_net_offset();
	else result = 0;
	
	time ((time_t *) &(tp->tv_sec));

	tp->tv_sec = tp->tv_sec - (66 * 365 * 24 * 60 * 60
            + 17 * 60 * 60 * 24) + net_offset;

	return (result);
}


#define TIME_PORT 37
#define TM_OFFSET 2208988800

/*
 *
 *   get_net_offset () -- Use UDP time protocol to figure out the
 *	offset between what the Mac thinks the time is an what
 *	the network thinks.
 *
 */
int
get_net_offset()
{
     time_t tv;
     char buf[512],ts[256];
     long *nettime;
     int attempts, cc, time_port;
     long unixtime;
	 char	realm[REALM_SZ];
	 ip_addr	fromaddr;
	 unsigned short	fromport;
	 int result;
	 
     nettime = (long *)buf;
	 time_port = TIME_PORT;

	 cc = sizeof(buf);
	 result = hosts_send_recv(ts, 1, buf, &cc, "", time_port);
     time (&tv);
	 
	 if (result!=KSUCCESS || cc<4) {
	 	net_offset = 0;
	 	if (!result) result = 100;
	 	return result;
	 }
						
     unixtime = (long) ntohl(*nettime) - TM_OFFSET;

     tv  -= 66 * 365 * 24 * 60 * 60
	  + 17 * 60 * 60 * 24;			/* Convert to unix time w/o offset */
     net_offset = unixtime - tv;
     net_got_offset = 1;
     
     return 0;
}

#endif
