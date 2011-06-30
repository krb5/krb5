.. _slave_host_key_label:

Create host keys for the Slave KDCs
========================================

Each KDC needs a host principal in the Kerberos database. You can enter these from any host, once the *kadmind* daemon is running. For example, if your master KDC were called *kerberos.mit.edu*, and you had two KDC slaves named *kerberos-1.mit.edu* and *kerberos-2.mit.edu*, you would type the following::

     shell% /usr/local/sbin/kadmin
     kadmin: addprinc -randkey host/kerberos.mit.edu
     NOTICE: no policy specified for "host/kerberos.mit.edu@ATHENA.MIT.EDU";
     assigning "default"
     Principal "host/kerberos.mit.edu@ATHENA.MIT.EDU" created.
     kadmin: addprinc -randkey host/kerberos-1.mit.edu
     NOTICE: no policy specified for "host/kerberos-1.mit.edu@ATHENA.MIT.EDU";
     assigning "default"
     Principal "host/kerberos-1.mit.edu@ATHENA.MIT.EDU" created.
     kadmin: addprinc -randkey host/kerberos-2.mit.edu
     NOTICE: no policy specified for "host/kerberos-2.mit.edu@ATHENA.MIT.EDU";
     assigning "default"
     Principal "host/kerberos-2.mit.edu@ATHENA.MIT.EDU" created.
     kadmin:
     

It is not actually necessary to have the master KDC server in the Kerberos database, but it can be handy if:

- anyone will be logging into the machine as something other than root
- you want to be able to swap the master KDC with one of the slaves if necessary. 


Extract host keytabs for the KDCs
=====================================

Each KDC (including the master) needs a keytab to decrypt tickets. Ideally, you should extract each keytab locally on its own KDC. If this is not feasible, you should use an encrypted session to send them across the network. To extract a keytab on a KDC called *kerberos.mit.edu*, you would execute the following command::

     kadmin: ktadd host/kerberos.mit.edu
     kadmin: Entry for principal host/kerberos.mit.edu@ATHENA.MIT.EDU with
          kvno 1, encryption type DES-CBC-CRC added to keytab
          WRFILE:/etc/krb5.keytab.
     kadmin:
     

.. note:: Principal must exist in the Kerberos database in order to extract the keytab.

Set Up the Slave KDCs for Database Propagation
=================================================

The database is propagated from the master KDC to the slave KDCs via the kpropd daemon. To set up propagation, create a file on each KDC, named */usr/local/var/krb5kdc/kpropd.acl*, containing the principals for each of the KDCs. For example, if the master KDC were *kerberos.mit.edu*, the slave KDCs were *kerberos-1.mit.edu* and *kerberos-2.mit.edu*, and the realm were *ATHENA.MIT.EDU*, then the file's contents would be::

     host/kerberos.mit.edu@ATHENA.MIT.EDU
     host/kerberos-1.mit.edu@ATHENA.MIT.EDU
     host/kerberos-2.mit.edu@ATHENA.MIT.EDU
     

Then, add the following line to */etc/inetd.conf* file on each KDC::

     krb5_prop stream tcp nowait root /usr/local/sbin/kpropd kpropd
     

You also need to add the following lines to */etc/services* on each KDC::

     kerberos        88/udp      kdc       # Kerberos authentication (udp)
     kerberos        88/tcp      kdc       # Kerberos authentication (tcp)
     krb5_prop       754/tcp               # Kerberos slave propagation
     kerberos-adm    749/tcp               # Kerberos 5 admin/changepw (tcp)
     kerberos-adm    749/udp               # Kerberos 5 admin/changepw (udp)
     

------------

Feedback:

Please, provide your feedback or suggest a new topic at krb5-bugs@mit.edu?subject=Documentation___install_kdc




