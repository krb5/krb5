.. _admin_acl_label:

Add administrators to the ACL file
======================================

Next, you need create an Access Control List (acl) file, and put the Kerberos principal of at least one of the administrators into it. This file is used by the kadmind daemon to control which principals may view and make privileged modifications to the Kerberos database files. The filename should match the value you have set for "acl_file" (see :ref:`kdc_realms`) in your kdc.conf file. The default file name is /usr/local/var/krb5kdc/kadm5.acl.

The format of the file is:

     Kerberos_principal      permissions     [target_principal]	[restrictions]
     

The Kerberos principal (and optional target principal) can include the "*" wildcard, so if you want any principal with the instance "admin" to have full permissions on the database, you could use the principal "\*\/admin\@REALM" where "REALM" is your Kerberos realm. target_principal can also include backreferences to Kerberos_principal, in which "\*number" matches the component number in the Kerberos_principal.

Note: a common use of an admin instance is so you can grant separate permissions (such as administrator access to the Kerberos database) to a separate Kerberos principal. For example, the user *joeadmin* might have a principal for his administrative use, called *joeadmin/admin*. This way, *joeadmin* would obtain *joeadmin/admin* tickets only when he actually needs to use those permissions.

The permissions are represented by single letters; UPPER-CASE letters represent negative permissions. The permissions are:

==== ==========================================================
a    allows the addition of principals or policies in the database. 
A    disallows the addition of principals or policies in the database. 
c    allows the changing of passwords for principals in the database. 
C    disallows the changing of passwords for principals in the database. 
d    allows the deletion of principals or policies in the database. 
D    disallows the deletion of principals or policies in the database. 
i    allows inquiries to the database. 
I    disallows inquiries to the database. 
l    allows the listing of principals or policies in the database. 
L    disallows the listing of principals or policies in the database. 
m    allows the modification of principals or policies in the database. 
M    disallows the modification of principals or policies in the database. 
s    allows the explicit setting of the key for a principal 
S    disallows the explicit setting of the key for a principal 
\*   All privileges (admcil). 
x    All privileges (admcil); identical to "\*". 
==== ==========================================================

The restrictions are a string of flags. Allowed restrictions are:

==================== ===============================
[+\|-]flagname        flag is forced to indicated value. The permissible flags are the same as the + and - flags for the kadmin *addprinc* and *modprinc* commands. 
-clearpolicy          policy is forced to clear 
-policy *pol*         policy is forced to be *pol* 
expire *time*
pwexpire *time*
maxlife *time*
maxrenewlife *time*    associated value will be forced to MIN(*time*, requested value) 
==================== ===============================

The above flags act as restrictions on any add or modify operation which is allowed due to that ACL line.

Here is an example of a *kadm5.acl* file. 

.. warning::  The order is important; permissions are determined by the first matching entry.

::

     */admin@ATHENA.MIT.EDU  *
     joeadmin@ATHENA.MIT.EDU  ADMCIL
     joeadmin/*@ATHENA.MIT.EDU il */root@ATHENA.MIT.EDU
     *@ATHENA.MIT.EDU cil *1/admin@ATHENA.MIT.EDU
     */*@ATHENA.MIT.EDU  i
     */admin@EXAMPLE.COM * -maxlife 9h -postdateable
     

In the above file, any principal in the *ATHENA.MIT.EDU* realm with an admin instance has all administrative privileges. The user *joeadmin* has all permissions with his admin instance, *joeadmin\/admin\@ATHENA.MIT.EDU* (matches the first line). He has no permissions at all with his null instance, *joeadmin\@ATHENA.MIT.EDU* (matches the second line). His root instance has inquire and list permissions with any other principal that has the instance root. Any principal in *ATHENA.MIT.EDU* can inquire, list, or change the password of their admin instance, but not any other admin instance. Any principal in the realm *ATHENA.MIT.EDU* (except for *joeadmin\@ATHENA.MIT.EDU*, as mentioned above) has inquire privileges. Finally, any principal with an admin instance in *EXAMPLE.COM* has all permissions, but any principal that they create or modify will not be able to get postdateable tickets or tickets with a life of longer than 9 hours. 

------------

Feedback:

Please, provide your feedback or suggest a new topic at krb5-bugs@mit.edu?subject=Documentation___install_kdc


