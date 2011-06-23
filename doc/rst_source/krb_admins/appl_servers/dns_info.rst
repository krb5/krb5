Getting DNS information correct
===================================

Several aspects of Kerberos rely on name service. In order for Kerberos to provide its high level of security, it is less forgiving of name service problems than some other parts of your network. It is important that your Domain Name System (DNS) entries and your hosts have the correct information.

Each host's canonical name must be the fully-qualified host name (including the domain), and each host's IP address must reverse-resolve to the canonical name.

Other than the localhost entry, make all entries in each machine's /etc/hosts file in the following form::

     IP address      fully-qualified hostname        aliases
     

Here is a sample */etc/hosts* file::

     # this is a comment
     127.0.0.1       localhost localhost@mit.edu
     10.0.0.6       daffodil.mit.edu trillium wake-robin
     

Additionally, on Solaris machines, you need to be sure the "hosts" entry in the file */etc/nsswitch.conf* includes the source "dns" as well as "file".

Finally, each host's keytab file must include a host/key pair for the host's canonical name. You can list the keys in a keytab file by issuing the command *klist -k*. For example::

     viola# klist -k
     Keytab name: /etc/krb5.keytab
     KVNO Principal
     ---- ------------------------------------------------------------
        1 host/daffodil.mit.edu@ATHENA.MIT.EDU
     

If you telnet to the host with a fresh credentials cache (ticket file), and then *klist*, the host's service principal should be::

      host/fully-qualified-hostname@REALM_NAME. 

----------------------

Feedback:

Please, provide your feedback at krb5-bugs@mit.edu?subject=Documentation___appl_servers

