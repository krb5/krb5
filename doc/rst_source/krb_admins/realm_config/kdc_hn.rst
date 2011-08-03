.. _kdc_hn_label:



Hostnames for KDCs
==========================

.. note:: This document was copied from **Kerberos V5 System Administrator's Guide** with minor changes. Currently it is under review. Please, send your feedback, corrections and additions to krb5-bugs@mit.edu. Your contribution is greatly appreciated.

MIT recommends that your KDCs have a predefined set of CNAME records (DNS hostname aliases), such as *kerberos* for the master KDC and *kerberos-1, kerberos-2, ...* for the slave KDCs. This way, if you need to swap a machine, you only need to change a DNS entry, rather than having to change hostnames.

A new mechanism for locating KDCs of a realm through DNS has been added to the MIT Kerberos V5 distribution. A relatively new record type called SRV has been added to DNS. Looked up by a service name and a domain name, these records indicate the hostname and port number to contact for that service, optionally with weighting and prioritization. (See :rfc:`2782` if you want more information. You can follow the example below for straightforward cases.)

The use with Kerberos is fairly straightforward. The domain name used in the SRV record name is the domain-style Kerberos realm name. (It is possible to have Kerberos realm names that are not DNS-style names, but we don't recommend it for Internet use, and our code does not support it well.) Several different Kerberos-related service names are used:

_kerberos._udp
    This is for contacting any KDC by UDP. This entry will be used the most often. Normally you should list port 88 on each of your KDCs.
_kerberos._tcp
    This is for contacting any KDC by TCP. The MIT KDC by default will not listen on any TCP ports, so unless you've changed the configuration or you're running another KDC implementation, you should leave this unspecified. If you do enable TCP support, normally you should use port 88.
_kerberos-master._udp
    This entry should refer to those KDCs, if any, that will immediately see password changes to the Kerberos database. This entry is used only in one case, when the user is logging in and the password appears to be incorrect; the master KDC is then contacted, and the same password used to try to decrypt the response, in case the user's password had recently been changed and the first KDC contacted hadn't been updated. Only if that fails is an "incorrect password" error given.

    If you have only one KDC, or for whatever reason there is no accessible KDC that would get database changes faster than the others, you do not need to define this entry.
_kerberos-adm._tcp
    This should list port 749 on your master KDC. Support for it is not complete at this time, but it will eventually be used by the kadmin program and related utilities. For now, you will also need the admin_server entry in :ref:`krb5.conf`.
_kpasswd._udp
    This should list port 464 on your master KDC. It is used when a user changes her password. 

Be aware, however, that the DNS SRV specification requires that the hostnames listed be the canonical names, not aliases. So, for example, you might include the following records in your (BIND-style) zone file::

     $ORIGIN foobar.com.
     _kerberos               TXT       "FOOBAR.COM"
     kerberos                CNAME     daisy
     kerberos-1              CNAME     use-the-force-luke
     kerberos-2              CNAME     bunny-rabbit
     _kerberos._udp          SRV       0 0 88 daisy
                             SRV       0 0 88 use-the-force-luke
                             SRV       0 0 88 bunny-rabbit
     _kerberos-master._udp   SRV       0 0 88 daisy
     _kerberos-adm._tcp      SRV       0 0 749 daisy
     _kpasswd._udp           SRV       0 0 464 daisy
     

As with the DNS-based mechanism for determining the Kerberos realm of a host, we recommend distributing the information this way for use by other sites that may want to interact with yours using Kerberos, even if you don't immediately make use of it within your own site. If you anticipate installing a very large number of machines on which it will be hard to update the Kerberos configuration files, you may wish to do all of your Kerberos service lookups via DNS and not put the information (except for *admin_server* as noted above) in future versions of your krb5.conf files at all. Eventually, we hope to phase out the listing of server hostnames in the client-side configuration files; making preparations now will make the transition easier in the future. 

--------------

Feedback

Please, provide your feedback or suggest a new topic at krb5-bugs@mit.edu?subject=Documentation___hostnames



