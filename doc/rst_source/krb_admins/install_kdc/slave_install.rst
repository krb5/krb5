.. _slave_host_key_label:

Setting up slave KDCs
========================================

Prep work on the master side.
-------------------------------------------

Each KDC needs a *host* keys in the Kerberos database.
These keys are used for mutual authentication when propagating the database
*dump* file from the master KDC to the secondary KDC servers.

On the master KDC connect to administrative interface and create
the new principals for each of the KDCs *host* service.
For example, if the master KDC were called *kerberos.mit.edu*, and you had
slave KDC named *kerberos-1.mit.edu*, you would type the following::

     shell% /usr/local/bin/kadmin
     kadmin: addprinc -randkey host/kerberos.mit.edu
     NOTICE: no policy specified for "host/kerberos.mit.edu@ATHENA.MIT.EDU"; assigning "default"
     Principal "host/kerberos.mit.edu@ATHENA.MIT.EDU" created.

     kadmin: addprinc -randkey host/kerberos-1.mit.edu
     NOTICE: no policy specified for "host/kerberos-1.mit.edu@ATHENA.MIT.EDU"; assigning "default"
     Principal "host/kerberos-1.mit.edu@ATHENA.MIT.EDU" created.


It is not actually necessary to have the master KDC server in the Kerberos
database, but it can be handy if:

   - anyone will be logging into the machine as something other than *root*
   - you want to be able to swap the master KDC with one of the slaves if necessary.

Next, extract *host* random keys for all participating KDCs and store them
in the default keytab file which is needed to decrypt tickets.
Ideally, you should extract each keytab locally on its own KDC.
If this is not feasible, you should use an encrypted session to send them across the network.
To extract a keytab on a KDC called *kerberos.mit.edu*, you would execute the following command::

     kadmin: ktadd host/kerberos.mit.edu
     kadmin: Entry for principal host/kerberos.mit.edu@ATHENA.MIT.EDU with
          kvno 1, encryption type DES-CBC-CRC added to keytab WRFILE:/etc/krb5.keytab.

     kadmin: ktadd -k /tmp/krb5.keytab host/kerberos-1.mit.edu
     kadmin: Entry for principal host/kerberos-1.mit.edu@ATHENA.MIT.EDU with
          kvno 1, encryption type DES-CBC-CRC added to keytab WRFILE:/tmp/krb5.keytab.

     kadmin:
     
Move the file /tmp/krb5.keytab (via scp) onto the slave KDC (*kerberos-1.mit.edu*)
into exactly the same location as on the master (default is */etc/krb5.keytab*).
Remove the temporary copy /tmp/krb5.keytab from the master.


Configuring the slave
-------------------------

By default, the propagation is done on the entire content of the master's database.
That is, even special principals (like *K/M\@FOOBAR.COM*) will be dumped and
copied to the slave KDCs.
Pay attention there: it means that configuration files, as also specific files
(like ACLs and :ref:`stash_definition`) must be copied to the slave hosts too.
Copying only a part of it will result in a bulky situation.
If you forget to copy the stash file for example,
the KDC daemon on the slave host will not be able to access the propagated
database because of missing master key.
Before connecting to the slave, you will copy all minimum required files
from the master for the slave system to work.  Initially, it concerns
(See :ref:`mitK5defaults` for the recommended default locations for these files):

   • krb5.conf 
   • kdc.conf 
   • kadm5.acl 
   • master key stash file 

Connect to the slave, *kerberos-1.mit.edu*. Move the copied files into their
appropriate directories (exactly like on the master KDC).

You will now initialize the slave database::

      shell%  /usr/local/sbin/kdb5_util create

.. caution:: You will use :ref:`kdb5_util(8)` but without exporting the stash file (-s argument), i
             thus avoiding the obliteration of the one you just copied from the master.

When asking for the database Master Password, type in anything you want.
The whole dummy database will be erased upon the first propagation from master.

The database is propagated from the master KDC to the slave KDCs via
the :ref:`kpropd(8)` daemon.
You must explicitly specify the clients that are allowed to provide Kerberos
dump updates on the slave machine with a new database.
The *kpropd.acl* file serves as the access control list for the *kpropd* service.
This file is typically resides in *krb5kdc* local directory.
Since in our case the updates should only come from *kerberos.mit.edu* server,
then the file's contents would be::

     host/kerberos.mit.edu@ATHENA.MIT.EDU

.. note:: If you expect that the primary and secondary KDCs will be switched at some point of time, 
          it is recommended to list the  host principals from *all* participating KDC servers in 
          *kpropd.acl* files on *all* of these servers.  


Then, add the following line to */etc/inetd.conf* file on each KDC
(Adjust the path to *kpropd*)::

     krb5_prop stream tcp nowait root /usr/local/sbin/kpropd kpropd
     eklogin stream tcp nowait root  /usr/local/sbin/klogind klogind -5 -c -e

You also need to add the following lines to */etc/services* on each KDC
(assuming that default ports are used)::

     kerberos        88/udp      kdc       # Kerberos authentication (udp)
     kerberos        88/tcp      kdc       # Kerberos authentication (tcp)
     krb5_prop       754/tcp               # Kerberos slave propagation
     kerberos-adm    749/tcp               # Kerberos 5 admin/changepw (tcp)
     kerberos-adm    749/udp               # Kerberos 5 admin/changepw (udp)

Restart *inetd* daemon.


Alternatively, start :ref:`kpropd(8)` as a stand-alone daemon "kpropd -S" or,
if the default locations must be overridden,::

    shell% /usr/local/sbin/kpropd -S -a path-to-kpropd.acl -r ATHENA.MIT.EDU -f /var/krb5kdc/from_master

    waiting for a kprop connection

Now that the slave KDC is able to accept database propagation,
you’ll need to propagate the database from the master server.

NOTE: Do not start slave KDC -  you still do not have a copy of the master's database.

------------

Feedback:

Please, provide your feedback or suggest a new topic at krb5-bugs@mit.edu?subject=Documentation___install_kdc

