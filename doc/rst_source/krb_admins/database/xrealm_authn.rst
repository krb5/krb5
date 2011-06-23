.. _xrealm_authn_label:

Cross-realm authentication
============================

In order for a KDC in one realm to authenticate Kerberos users in a different realm, it must share a key with the KDC in the other realm. In both databases, there must be krbtgt service principals for realms. These principals should all have the same passwords, key version numbers, and encryption types. 

For example, if the administrators of ATHENA.MIT.EDU and EXAMPLE.COM wanted to authenticate across the realms, they would run the following commands on the KDCs in both realms::

     shell%: kadmin.local -e "des3-hmac-sha1:normal des-cbc-crc:v4"
     kadmin: addprinc -requires_preauth krbtgt/ATHENA.MIT.EDU@EXAMPLE.COM
     Enter password for principal krbtgt/ATHENA.MIT.EDU@EXAMPLE.COM:
     Re-enter password for principal krbtgt/ATHENA.MIT.EDU@EXAMPLE.COM:
     kadmin: addprinc -requires_preauth krbtgt/EXAMPLE.COM@ATHENA.MIT.EDU
     Enter password for principal krbtgt/EXAMPLE.COM@ATHENA.MIT.EDU:
     Enter password for principal krbtgt/EXAMPLE.COM@ATHENA.MIT.EDU:
     kadmin:
     
.. note:: Even if most principals in a realm are generally created with the *requires_preauth* flag enabled, this flag is not desirable on cross-realm authentication keys because doing so makes it impossible to disable preauthentication on a service-by-service basis. Disabling it as in the example above is recommended.


.. note:: It is very important that these principals have good passwords. MIT recommends that TGT principal passwords be at least 26 characters of random ASCII textck:

------------

Feedback:

Please, provide your feedback at krb5-bugs@mit.edu?subject=Documentation___db


