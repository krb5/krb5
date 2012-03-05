Application servers
===================

If you need to install the Kerberos V5 programs on an application
server, please refer to the Kerberos V5 Installation Guide.  Once you
have installed the software, you need to add that host to the Kerberos
database (see :ref:`add_mod_del_princs`), and generate a keytab for
that host, that contains the host's key.  You also need to make sure
the host's clock is within your maximum clock skew of the KDCs.


Keytabs
-------

A keytab is a host's copy of its own keylist, which is analogous to a
user's password.  An application server that needs to authenticate
itself to the KDC has to have a keytab that contains its own principal
and key.  Just as it is important for users to protect their
passwords, it is equally important for hosts to protect their keytabs.
You should always store keytab files on local disk, and make them
readable only by root, and you should never send a keytab file over a
network in the clear.  Ideally, you should run the :ref:`kadmin(1)`
command to extract a keytab on the host on which the keytab is to
reside.


.. _add_princ_kt:

Adding principals to keytabs
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

To generate a keytab, or to add a principal to an existing keytab, use
the **ktadd** command from kadmin.

.. include:: admin_commands/kadmin_local.rst
   :start-after:  _ktadd:
   :end-before: _ktadd_end:

.. note:: Alternatively, the keytab can be generated using
          :ref:`ktutil(1)` **add_entry -password** and **write_kt**
          commands.


Examples
########

Here is a sample session, using configuration files that enable only
*des-cbc-crc* encryption::

    kadmin: ktadd host/daffodil.mit.edu@ATHENA.MIT.EDU
    kadmin: Entry for principal host/daffodil.mit.edu@ATHENA.MIT.EDU with kvno 2, encryption type DES-CBC-CRC added to keytab WRFILE:/etc/krb5.keytab.
    kadmin:

    kadmin: ktadd -k /usr/local/var/krb5kdc/kadmind.keytab kadmin/admin kadmin/changepw
    kadmin: Entry for principal kadmin/admin@ATHENA.MIT.EDU with kvno 3, encryption type DES-CBC-CRC added to keytab WRFILE:/usr/local/var/krb5kdc/kadmind.keytab.
    kadmin:


Removing principals from keytabs
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

To remove a principal from an existing keytab, use the kadmin
**ktremove** command.

.. include:: admin_commands/kadmin_local.rst
   :start-after:  _ktremove:
   :end-before: _ktremove_end:


Clock Skew
----------

In order to prevent intruders from resetting their system clocks in
order to continue to use expired tickets, Kerberos V5 is set up to
reject ticket requests from any host whose clock is not within the
specified maximum clock skew of the KDC (as specified in the KDC's
:ref:`krb5.conf(5)` file).  Similarly, hosts are configured to reject
responses from any KDC whose clock is not within the specified maximum
clock skew of the host (as specified in the :ref:`krb5.conf(5)` file).
The default value for maximum clock skew is 300 seconds, or five
minutes.  MIT suggests that you add a line to client machines'
``/etc/rc`` files to synchronize the machine's clock to your KDC at
boot time. On UNIX hosts, assuming you had a kdc called kerberos in
your realm, this would be::

    gettime -s kerberos

If the host is not likely to be rebooted frequently, you may also want
to set up a cron job that adjusts the time on a regular basis.


Getting DNS information correct
-------------------------------

Several aspects of Kerberos rely on name service.  In order for
Kerberos to provide its high level of security, it is less forgiving
of name service problems than some other parts of your network.  It is
important that your Domain Name System (DNS) entries and your hosts
have the correct information.

Each host's canonical name must be the fully-qualified host name
(including the domain), and each host's IP address must
reverse-resolve to the canonical name.

Other than the localhost entry, make all entries in each machine's
/etc/hosts file in the following form::

    IP address      fully-qualified hostname        aliases

Here is a sample ``/etc/hosts`` file::

    # this is a comment
    127.0.0.1      localhost localhost@mit.edu
    10.0.0.6       daffodil.mit.edu trillium wake-robin

Additionally, on Solaris machines, you need to be sure the ``hosts``
entry in the file ``/etc/nsswitch.conf`` includes the source ``dns``
as well as ``file``.

Finally, each host's keytab file must include a host/key pair for the
host's canonical name.  You can list the keys in a keytab file by
issuing the command ``klist -k``. For example::

    viola# klist -k
    Keytab name: /etc/krb5.keytab
    KVNO Principal
    ---- ------------------------------------------------------------
       1 host/daffodil.mit.edu@ATHENA.MIT.EDU

If you telnet to the host with a fresh credentials cache (ticket
file), and then :ref:`klist(1)`, the host's service principal should
be::

    host/fully-qualified-hostname@REALM_NAME.


.. _conf_firewall:

Configuring your firewall to work with Kerberos V5
--------------------------------------------------

If you need off-site users to be able to get Kerberos tickets in your
realm, they must be able to get to your KDC.  This requires either
that you have a slave KDC outside your firewall, or you configure your
firewall to allow UDP requests into at least one of your KDCs, on
whichever port the KDC is running.  (The default is port 88; other
ports may be specified in the KDC's :ref:`kdc.conf(5)` file.)
Similarly, if you need off-site users to be able to change their
passwords in your realm, they must be able to get to your Kerberos
admin server.  The default port for the admin server is 749.

If your on-site users inside your firewall will need to get to KDCs in
other realms, you will also need to configure your firewall to allow
outgoing TCP and UDP requests to port 88.  Additionally, if they will
need to get to any Kerberos V4 KDCs, you may also need to allow TCP
and UDP requests to port 750.  If your on-site users inside your
firewall will need to get to Kerberos admin servers in other realms,
you will also need to allow outgoing TCP and UDP requests to port 749.

If any of your KDCs are outside your firewall, you will need to allow
kprop requests to get through to the remote KDC.  :ref:`kprop(8)` uses
the ``krb5_prop`` service on port 754 (tcp).

If you need your off-site users to have access to machines inside your
firewall, you need to allow TCP connections from their off-site hosts
on the appropriate ports for the programs they will be using. The
following lines from ``/etc/services`` show the default port numbers
for the Kerberos V5 programs::

    ftp           21/tcp           # Kerberos ftp and telnet use the
    telnet        23/tcp           # default ports
    kerberos      88/udp    kdc    # Kerberos V5 KDC
    kerberos      88/tcp    kdc    # Kerberos V5 KDC
    klogin        543/tcp          # Kerberos authenticated rlogin
    kshell        544/tcp   cmd    # and remote shell
    kerberos-adm  749/tcp          # Kerberos 5 admin/changepw
    kerberos-adm  749/udp          # Kerberos 5 admin/changepw
    krb5_prop     754/tcp          # Kerberos slave propagation
    eklogin       2105/tcp         # Kerberos auth. & encrypted rlogin

By default, Kerberos V5 telnet and ftp use the same ports as the
standard telnet and ftp programs, so if you already allow telnet and
ftp connections through your firewall, the Kerberos V5 versions will
get through as well.  If you do not already allow telnet and ftp
connections through your firewall, but need your users to be able to
use Kerberos V5 telnet and ftp, you can either allow ftp and telnet
connections on the standard ports, or switch these programs to
non-default port numbers and allow ftp and telnet connections on those
ports to get through.  Kerberos V5 rlogin uses the ``klogin`` service,
which by default uses port 543.  Encrypted Kerberos V5 rlogin uses the
``eklogin`` service, which by default uses port 2105.  Kerberos V5 rsh
uses the kshell service, which by default uses port 544.  However, the
server must be able to make a TCP connection from the kshell port to
an arbitrary port on the client, so if your users are to be able to
use rsh from outside your firewall, the server they connect to must be
able to send outgoing packets to arbitrary port numbers.  Similarly,
if your users need to run rsh from inside your firewall to hosts
outside your firewall, the outside server needs to be able to connect
to an arbitrary port on the machine inside your firewall.  Because
Kerberos V5 rcp uses rsh, the same issues apply.  If you need to use
rsh (or rcp) through your firewall and are concerned with the security
implications of allowing connections to arbitrary ports, MIT suggests
that you have rules that specifically name these applications and, if
possible, list the allowed hosts.

The book UNIX System Security, by David Curry, is a good starting
point for learning to configure firewalls.


Feedback
--------

Please, provide your feedback at
krb5-bugs@mit.edu?subject=Documentation___appl_servers
