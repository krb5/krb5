# Copyright 2006 Massachusetts Institute of Technology.
# All Rights Reserved.
#
# Export of this software from the United States of America may
#   require a specific license from the United States Government.
#   It is the responsibility of any person or organization contemplating
#   export to obtain such a license before exporting.
# 
# WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
# distribute this software and its documentation for any purpose and
# without fee is hereby granted, provided that the above copyright
# notice appear in all copies and that both that copyright notice and
# this permission notice appear in supporting documentation, and that
# the name of M.I.T. not be used in advertising or publicity pertaining
# to distribution of the software without specific, written prior
# permission.  Furthermore if you modify this software you must label
# your software as modified software and not distribute it in such a
# fashion that it might be confused with the original M.I.T. software.
# M.I.T. makes no representations about the suitability of
# this software for any purpose.  It is provided "as is" without express
# or implied warranty.

# possible return values:
#  False: request not handled by this script, try another means
#  empty list: no server available, e.g., TCP KDC in realm with only UDP
#  ordered list of (ip-addr-string, port-number-or-string, socket-type)
#
# Field ip-addr-string is a numeric representation of the IPv4 or IPv6
# address.  Field port-number-or-string is, for example, "88" or 88.  The
# socket type is also expressed numerically, SOCK_DGRAM or SOCK_STREAM.
# It must agree with the supplied socktype value if that is non-zero, but
# zero must not be used in the returned list.
#
# service enum values: kdc=1, master_kdc, kadmin, krb524, kpasswd

from socket import getaddrinfo, SOCK_STREAM, SOCK_DGRAM, AF_INET, AF_INET6
def locate1 (service, realm, socktype, family):
   if (service == 1 or service == 2) and realm == "ATHENA.MIT.EDU":
      if socktype == SOCK_STREAM: return []
      socktype = SOCK_DGRAM
      result = []
      hlist = (("kerberos.mit.edu", 88), ("kerberos-1.mit.edu", 88),
	       ("some-random-name-that-does-not-exist.mit.edu", 12345),
	       ("kerberos.mit.edu", 750))
      if service == 2: hlist = (hlist[0],)
      for (hname,hport) in hlist:
	 try:
	    alist = getaddrinfo(hname, hport, family, socktype)
	    for a in alist:
	       (fam, stype, proto, canonname, sa) = a
	       if fam == AF_INET or fam == AF_INET6:
		  addr = sa[0]
		  port = sa[1]
		  result = result + [(addr, port, stype)]
	 except Exception, inst:
#           print "getaddrinfo error for " + hname + ":", inst
	    pass  # Enh, this is just a demo.
      return result
   if realm == "BOBO.MIT.EDU": return []
   return False

verbose = 0
servicenames = { 1: "kdc", 2: "master_kdc", 3: "kadmin", 4: "krb524", 5: "kpasswd" }
socktypenames = { SOCK_STREAM: "STREAM", SOCK_DGRAM: "DGRAM" }
familynames = { 0: "UNSPEC", AF_INET: "INET", AF_INET6: "INET6" }

def locate (service, realm, socktype, family):
   socktypename = socktype
   if socktype in socktypenames: socktypename = "%s(%d)" % (socktypenames[socktype], socktype)
   familyname = family
   if family in familynames: familyname = "%s(%d)" % (familynames[family], family)
   servicename = service
   if service in servicenames: servicename = "%s(%d)" % (servicenames[service], service)
   if verbose: print "locate called with service", servicename, "realm", realm, "socktype", socktypename, "family", familyname
   result = locate1 (service, realm, socktype, family)
   if verbose: print "locate result is", result
   return result
