.. _kpasswd(1):

kpasswd
===============================================


SYNOPSIS
~~~~~~~~~~~~~

*kpasswd* [ *principal* ]


DESCRIPTION
~~~~~~~~~~~~~

The *kpasswd* command is used to change a Kerberos principal's password.
*kpasswd* prompts for the current Kerberos password, which is used to obtain a 
*changepw* ticket from the KDC for the user's Kerberos realm.   
If *kpasswd* successfully obtains the *changepw* ticket, the user is prompted twice for
the new password, and the password is changed.

If the principal is governed by a policy that specifies the length and/or number of
character classes required in the new password, the new password must conform to the policy.
(The five character classes are lower case, upper case, numbers, punctuation, and all other characters.)


OPTIONS
~~~~~~~~~~~~~

*principal*
          Change the password for the Kerberos principal principal.
          Otherwise, *kpasswd* uses the principal name from an existing ccache if there is one;
          if not, the principal is derived from the identity of the user invoking the *kpasswd* command.


PORTS
~~~~~~~~~~~~~

*kpasswd* looks first for::

          kpasswd_server = host:port 

in the [*realms*] section of the *krb5.conf* file under the current realm.
If that is missing, *kpasswd* looks for the *admin_server* entry, but substitutes 464 for the port.


SEE ALSO
~~~~~~~~~~~~~

kadmin(8), kadmind(8)


BUGS
~~~~~

*kpasswd* may not work with multi-homed hosts running on the Solaris platform.

