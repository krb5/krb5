Client machine configuration files
=====================================


Each machine running Kerberos must have a */etc/krb5.conf* file. (See :ref:`krb5.conf`.)

Also, for most UNIX systems, you must add the appropriate Kerberos services to each client machine's */etc/services* file. If you are using the default configuration for Kerberos V5, you should be able to just insert the following code::

     kerberos      88/udp    kdc    # Kerberos V5 KDC
     kerberos      88/tcp    kdc    # Kerberos V5 KDC
     kerberos-adm  749/tcp          # Kerberos 5 admin/changepw
     kerberos-adm  749/udp          # Kerberos 5 admin/changepw
     krb5_prop     754/tcp          # Kerberos slave propagation
     krb524        4444/tcp         # Kerberos 5 to 4 ticket translator
     

------------

Feedback:

Please, provide your feedback or suggest a new topic at krb5-bugs@mit.edu?subject=Documentation___cl_install



