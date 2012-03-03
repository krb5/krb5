Realm configuration decisions
=============================

.. note:: This document was copied from **Kerberos V5 Installation
          Guide** with minor changes. Currently it is under review.
          Please, send your feedback, corrections and additions to
          krb5-bugs@mit.edu.  Your contribution is greatly
          appreciated.

Before installing Kerberos V5, it is necessary to consider the
following issues:

* The name of your Kerberos realm (or the name of each realm, if you
  need more than one).
* How you will map your hostnames onto Kerberos realms.
* Which ports your KDC and and kadmin (database access) services will
  use.
* How many slave KDCs you need and where they should be located.
* The hostnames of your master and slave KDCs.
* How frequently you will propagate the database from the master KDC
  to the slave KDCs.


Realm name
----------

Although your Kerberos realm can be any ASCII string, convention is to
make it the same as your domain name, in upper-case letters.

For example, hosts in the domain ``example.com`` would be in the
Kerberos realm::

    EXAMPLE.COM

If you need multiple Kerberos realms, MIT recommends that you use
descriptive names which end with your domain name, such as::

    BOSTON.EXAMPLE.COM
    HOUSTON.EXAMPLE.COM


.. _mapping_hostnames:

Mapping hostnames onto Kerberos realms
--------------------------------------

Mapping hostnames onto Kerberos realms is done in one of two ways.

The first mechanism, which has been in use for years in MIT-based
Kerberos distributions, works through a set of rules in the
:ref:`krb5.conf(5)` configuration file.  You can specify mappings for
an entire domain or subdomain, and/or on a hostname-by-hostname basis.
Since greater specificity takes precedence, you would do this by
specifying the mappings for a given domain or subdomain and listing
the exceptions.

The second mechanism works by looking up the information in special
TXT records in the Domain Name Service.  This is currently not used by
default because security holes could result if the DNS TXT records
were spoofed.  If this mechanism is enabled on the client, it will try
to look up a TXT record for the DNS name formed by putting the prefix
``_kerberos`` in front of the hostname in question. If that record is
not found, it will try using ``_kerberos`` and the host's domain name,
then its parent domain, and so forth.  So for the hostname
``BOSTON.ENGINEERING.FOOBAR.COM``, the names looked up would be::

    _kerberos.boston.engineering.foobar.com
    _kerberos.engineering.foobar.com
    _kerberos.foobar.com
    _kerberos.com

The value of the first TXT record found is taken as the realm name.
(Obviously, this doesn't work all that well if a host and a subdomain
have the same name, and different realms.  For example, if all the
hosts in the ``ENGINEERING.FOOBAR.COM`` domain are in the
``ENGINEERING.FOOBAR.COM`` realm, but a host named
``ENGINEERING.FOOBAR.COM`` is for some reason in another realm.  In
that case, you would set up TXT records for all hosts, rather than
relying on the fallback to the domain name.)

Even if you do not choose to use this mechanism within your site, you
may wish to set it up anyway, for use when interacting with other
sites.


Ports for the KDC and admin services
------------------------------------

The default ports used by Kerberos are port 88 for the KDC1 and port
749 for the admin server.  You can, however, choose to run on other
ports, as long as they are specified in each host's ``/etc/services``
and :ref:`krb5.conf(5)` files, and the :ref:`kdc.conf(5)` file on each
KDC.  For a more thorough treatment of port numbers used by the
Kerberos V5 programs, refer to the :ref:`conf_firewall`.


Slave KDCs
----------

Slave KDCs provide an additional source of Kerberos ticket-granting
services in the event of inaccessibility of the master KDC.  The
number of slave KDCs you need and the decision of where to place them,
both physically and logically, depends on the specifics of your
network.

All of the Kerberos authentication on your network requires that each
client be able to contact a KDC.  Therefore, you need to anticipate
any likely reason a KDC might be unavailable and have a slave KDC to
take up the slack.

Some considerations include:

* Have at least one slave KDC as a backup, for when the master KDC is
  down, is being upgraded, or is otherwise unavailable.
* If your network is split such that a network outage is likely to
  cause a network partition (some segment or segments of the network
  to become cut off or isolated from other segments), have a slave KDC
  accessible to each segment.
* If possible, have at least one slave KDC in a different building
  from the master, in case of power outages, fires, or other localized
  disasters.


.. _kdc_hostnames:

Hostnames for KDCs
------------------

MIT recommends that your KDCs have a predefined set of CNAME records
(DNS hostname aliases), such as ``kerberos`` for the master KDC and
``kerberos-1``, ``kerberos-2``, ... for the slave KDCs.  This way, if
you need to swap a machine, you only need to change a DNS entry,
rather than having to change hostnames.

A new mechanism for locating KDCs of a realm through DNS has been
added to the MIT Kerberos V5 distribution.  A relatively new record
type called SRV has been added to DNS.  Looked up by a service name
and a domain name, these records indicate the hostname and port number
to contact for that service, optionally with weighting and
prioritization.  (See :rfc:`2782` if you want more information. You
can follow the example below for straightforward cases.)

The use with Kerberos is fairly straightforward.  The domain name used
in the SRV record name is the domain-style Kerberos realm name.  (It
is possible to have Kerberos realm names that are not DNS-style names,
but we don't recommend it for Internet use, and our code does not
support it well.)  Several different Kerberos-related service names
are used:

_kerberos._udp
    This is for contacting any KDC by UDP.  This entry will be used
    the most often.  Normally you should list port 88 on each of your
    KDCs.
_kerberos._tcp
    This is for contacting any KDC by TCP.  The MIT KDC by default
    will not listen on any TCP ports, so unless you've changed the
    configuration or you're running another KDC implementation, you
    should leave this unspecified.  If you do enable TCP support,
    normally you should use port 88.
_kerberos-master._udp
    This entry should refer to those KDCs, if any, that will
    immediately see password changes to the Kerberos database.  This
    entry is used only in one case, when the user is logging in and
    the password appears to be incorrect; the master KDC is then
    contacted, and the same password used to try to decrypt the
    response, in case the user's password had recently been changed
    and the first KDC contacted hadn't been updated.  Only if that
    fails is an "incorrect password" error given.

    If you have only one KDC, or for whatever reason there is no
    accessible KDC that would get database changes faster than the
    others, you do not need to define this entry.
_kerberos-adm._tcp
    This should list port 749 on your master KDC.  Support for it is
    not complete at this time, but it will eventually be used by the
    :ref:`kadmin(1)` program and related utilities.  For now, you will
    also need the admin_server entry in :ref:`krb5.conf(5)`.
_kpasswd._udp
    This should list port 464 on your master KDC.  It is used when a
    user changes her password.

Be aware, however, that the DNS SRV specification requires that the
hostnames listed be the canonical names, not aliases.  So, for
example, you might include the following records in your (BIND-style)
zone file::

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

As with the DNS-based mechanism for determining the Kerberos realm of
a host, we recommend distributing the information this way for use by
other sites that may want to interact with yours using Kerberos, even
if you don't immediately make use of it within your own site.  If you
anticipate installing a very large number of machines on which it will
be hard to update the Kerberos configuration files, you may wish to do
all of your Kerberos service lookups via DNS and not put the
information (except for **admin_server** as noted above) in future
versions of your :ref:`krb5.conf(5)` files at all.  Eventually, we
hope to phase out the listing of server hostnames in the client-side
configuration files; making preparations now will make the transition
easier in the future.


.. _db_prop:

Database propagation
--------------------

The Kerberos database resides on the master KDC, and must be
propagated regularly (usually by a cron job) to the slave KDCs.  In
deciding how frequently the propagation should happen, you will need
to balance the amount of time the propagation takes against the
maximum reasonable amount of time a user should have to wait for a
password change to take effect.

If the propagation time is longer than this maximum reasonable time
(e.g., you have a particularly large database, you have a lot of
slaves, or you experience frequent network delays), you may wish to
cut down on your propagation delay by performing the propagation in
parallel.  To do this, have the master KDC propagate the database to
one set of slaves, and then have each of these slaves propagate the
database to additional slaves.

See also :ref:`incr_db_prop`


Feedback
--------

Please, provide your feedback or suggest a new topic at
krb5-bugs@mit.edu?subject=Documentation___realm_config
