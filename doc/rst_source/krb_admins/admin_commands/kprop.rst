.. _kprop(8):

kprop
=========


SYNOPSIS
-------------

**kprop**
          [**-r** *realm*] 
          [**-f** *file*] 
          [**-d**] 
          [**-P** *port*] 
          [**-s** *keytab*] 
          *slave_host*


DESCRIPTION
-------------

*kprop*  is used to propagate a Kerberos V5 database dump file from the master Kerberos server to a slave Kerberos server, 
which is specfied by *slave_host*.  This is done by transmitting the dumped database file to the slave server over an encrypted, secure channel.   
The dump file must be created by :ref:`kdb5_util(8)`.

OPTIONS
-------------

       **-r** *realm*
              Specifies the realm of the master server.

       **-f** *file*
              Specifies the filename where the dumped principal database file is to be found; by default the dumped database file is
              normally /usr/local/var/krb5kdc/slave_datatrans.

       **-P** *port*
              Specifies the port to use to contact the :ref:`kpropd(8)` server on the remote host.

       **-d**     
              Prints debugging information.

       **-s** *keytab*
              Specifies the location of the keytab file.


SEE ALSO
-------------

kpropd(8), kdb5_util(8), krb5kdc(8)

