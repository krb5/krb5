.. _mapping_hn_label:


Mapping hostnames onto Kerberos realms
=============================================

.. note:: This document was copied from **Kerberos V5 System Administrator's Guide** with minor changes. Currently it is under review. Please, send your feedback, corrections and additions to krb5-bugs@mit.edu. Your contribution is greatly appreciated.

Mapping hostnames onto Kerberos realms is done in one of two ways.

The first mechanism, which has been in use for years in MIT-based Kerberos distributions, works through a set of rules in the :ref:`krb5.conf` configuration file.  You can specify mappings for an entire domain or subdomain, and/or on a hostname-by-hostname basis. Since greater specificity takes precedence, you would do this by specifying the mappings for a given domain or subdomain and listing the exceptions.

The second mechanism works by looking up the information in special TXT records in the Domain Name Service. This is currently not used by default because security holes could result if the DNS TXT records were spoofed. If this mechanism is enabled on the client, it will try to look up a TXT record for the DNS name formed by putting the prefix _kerberos in front of the hostname in question. If that record is not found, it will try using _kerberos and the host's domain name, then its parent domain, and so forth. So for the hostname *BOSTON.ENGINEERING.FOOBAR.COM*, the names looked up would be::

     _kerberos.boston.engineering.foobar.com
     _kerberos.engineering.foobar.com
     _kerberos.foobar.com
     _kerberos.com
     

The value of the first TXT record found is taken as the realm name. (Obviously, this doesn't work all that well if a host and a subdomain have the same name, and different realms. For example, if all the hosts in the *ENGINEERING.FOOBAR.COM* domain are in the *ENGINEERING.FOOBAR.COM* realm, but a host named *ENGINEERING.FOOBAR.COM* is for some reason in another realm. In that case, you would set up TXT records for all hosts, rather than relying on the fallback to the domain name.)

Even if you do not choose to use this mechanism within your site, you may wish to set it up anyway, for use when interacting with other sites. 


--------------

Feedback

Please, provide your feedback or suggest a new topic at krb5-bugs@mit.edu?subject=Documentation___hostnames



