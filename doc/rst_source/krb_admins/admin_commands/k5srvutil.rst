.. _k5srvutil(1):

k5srvutil
=============================================================

SYNOPSIS
----------

**k5srvutil** *operation* [ **-i** ] [ **-f** *filename* ]

DESCRIPTION
-------------

*k5srvutil* allows a system manager to list or change keys currently in his keytab or to add new keys to the keytab.

Operation must be one of the following:

       **list**
                 Lists the keys in a keytab showing version number and principal name.

       **change**
                 Changes all the keys in the keytab to new randomly-generated keys,
                 updating the keys in the Kerberos server's database to match by using the kadmin protocol.
                 If a key's version number doesn't match the version number stored in the Kerberos server's database,
                 then the operation will fail. The old keys are retained so that existing tickets continue to work.
                 If the *-i* flag is given, *k5srvutil* will prompt for yes or no before changing each key.
                 If the *-k* option is used, the old and new keys will be displayed.

       **delold**
                 Deletes keys that are not the most recent version from the keytab.
                 This operation should be used some time after a change operation to remove old keys.
                 If the *-i* flag is used, then the program prompts the user whether the old keys associated
                 with each principal should be removed.

       **delete**
                 Deletes particular keys in the keytab, interactively prompting for each key.


In all cases, the default file used is /etc/krb5.keytab file unless this is overridden by the **-f** option.


*k5srvutil*  uses the kadmin program to edit the keytab in place.
However, old keys are retained, so they are available in case of failure.


SEE ALSO
-------------

kadmin(8), ktutil(8)


