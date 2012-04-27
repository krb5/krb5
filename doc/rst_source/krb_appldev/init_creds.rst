Initial credentials
===================

Software that performs tasks such as logging users into a computer
when they type their Kerberos password needs to get initial
credentials (usually ticket granting tickets) from Kerberos.  Such
software shares some behavior with the :ref:`kinit(1)` program.

Whenever a program grants access to a resource (such as a local login
session on a desktop computer) based on a user successfully getting
initial Kerberos credentials, it must verify those credentials against
a secure shared secret (e.g., a host keytab) to ensure that the user
credentials actually originate from a legitimate KDC.  Failure to
perform this verification is a critical vulnerability, because a
malicious user can execute the "Zanarotti attack": the user constructs
a fake response that appears to come from the legitimate KDC, but
whose contents come from an attacker-controlled KDC.

Some applications read a Kerberos password over the network (ideally
over a secure channel), which they then verify against the KDC.  While
this technique may be the only practical way to integrate Kerberos
into some existing legacy systems, its use is contrary to the original
design goals of Kerberos.

The function :c:func:`krb5_get_init_creds_password` will get initial
credentials for a client using a password.  An application that needs
to verify the credentials can call :c:func:`krb5_verify_init_creds`.

Options for get_init_creds
--------------------------

The function :c:func:`krb5_get_init_creds_password` takes an options
parameter (which can be a null pointer).  Use the function
:c:func:`krb5_get_init_creds_opt_alloc` to allocate an options
structure, and :c:func:`krb5_get_init_creds_opt_free` to free it.

Verifying initial credentials
-----------------------------

Use the function :c:func:`krb5_verify_init_creds` to verify initial
credentials.  It takes an options structure (which can be a null
pointer).  Use :c:func:`krb5_verify_init_creds_opt_init` to initialize
the caller-allocated options structure, and
:c:func:`krb5_verify_init_creds_opt_set_ap_req_nofail` to set the
"nofail" option.

The confusingly named "nofail" option, when set, means that the
verification must actually succeed in order for
:c:func:`krb5_verify_init_creds` to indicate success.  The default
state of this option (cleared) means that if there is no key material
available to verify the user credentials, the verification will
succeed anyway.  (The default can be changed by a configuration file
setting.)

This accommodates a use case where a large number of unkeyed shared
desktop workstations need to allow users to log in using Kerberos.
The security risks from this practice are mitigated by the absence of
valuable state on the shared workstations -- any valuable resources
that the users would access reside on networked servers.
