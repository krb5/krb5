.. _khostrealm(1):

khostrealm
==========

SYNOPSIS
--------

**khostrealm**
[**-f**]
[**--**]
*host1 host2* ...


DESCRIPTION
-----------

khostrealm looks up a realm name for given host names.  It uses the
hostrealm plugin API, which includes looking for DNSSEC-assured
``_kerberos TXT`` records under the host names if ``dnssec_lookup_realm``
was not disabled in krb5.conf.

The output contains one line for each host name, and each line a space-separated
list of realms.  Usually, there is just one realm on a line.  Zero realms
indicate a failure to locate one.

The command starts with an emtpy validation cache, so it may take a while for
the first query to complete.  Subsequent queries to the same or overlapping
names will be served from the cache, and should resolve much faster.  Each
host is looked up independently, and printed immediately.  This makes
khostrealm suitable for testing DNSSEC performance.

The program exits with value 0 only when all hosts were resolved to at least
one realm: otherwise it exits with value 1.


OPTIONS
-------

**-f**
    Do not use the DNSSEC-protected method; instead use the fallback
    method.  This may also involve iterating upward in DNS.


ENVIRONMENT
-----------

khostrealm does not use any environment variables.


FILES
-----

khostrealm does not use any files.


SEE ALSO
--------

:ref:`krb5.conf(5)`
