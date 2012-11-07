.. _k5srvutil(1):

k5srvutil
=========

SYNOPSIS
--------

**k5srvutil** *operation*
[**-i**]
[**-f** *filename*]

DESCRIPTION
-----------

k5srvutil allows an administrator to list or change keys currently in
a keytab or to add new keys to the keytab.

*operation* must be one of the following:

**list**
    Lists the keys in a keytab showing version number and principal
    name.

**change**
    Uses the kadmin protocol to update the keys in the Kerberos
    database to new randomly-generated keys, and updates the keys in
    the keytab to match.  If a key's version number doesn't match the
    version number stored in the Kerberos server's database, then the
    operation will fail.  Old keys are retained in the keytab so that
    existing tickets continue to work.  If the **-i** flag is given,
    k5srvutil will prompt for confirmation before changing each key.
    If the **-k** option is given, the old and new keys will be
    displayed.

**delold**
    Deletes keys that are not the most recent version from the keytab.
    This operation should be used some time after a change operation
    to remove old keys, after existing tickets issued for the service
    have expired.  If the **-i** flag is given, then k5srvutil will
    prompt for confirmation for each principal.

**delete**
    Deletes particular keys in the keytab, interactively prompting for
    each key.

In all cases, the default keytab is used unless this is overridden by
the **-f** option.

k5srvutil uses the :ref:`kadmin(1)` program to edit the keytab in
place.


SEE ALSO
--------

:ref:`kadmin(1)`, :ref:`ktutil(1)`
