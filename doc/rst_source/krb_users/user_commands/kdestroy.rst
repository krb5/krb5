kdestroy - destroy Kerberos tickets
=======================================

SYNOPSIS
~~~~~~~~~~~~~

*kdestroy*
         [**-A**]
         [**-q**]
         [**-c** *cache_name*]


DESCRIPTION
~~~~~~~~~~~~~

The *kdestroy* utility destroys the user's active Kerberos
authorization tickets by writing zeros to the specified
credentials cache that contains them. If the credentials
cache is not specified, the default credentials cache is destroyed.


OPTIONS
~~~~~~~~~~~~~

     **-A**
        Destroys all caches in the collection, if a cache collection is
        available.

     **-q**
        Run quietly. Normally *kdestroy* beeps if it fails to destroy the user's tickets. The *-q* flag suppresses this behavior.

     **-c** *cache_name*
        Use *cache_name* as the credentials (ticket) cache name and location;
        if this option is not used, the default cache name and location are used.

        The default credentials cache may vary between systems.
        If the **KRB5CCNAME** environment variable is set, its
        value is used to name the default ticket cache.


NOTE
~~~~~

Most installations recommend that you place the *kdestroy* command in your *.logout* file, 
so that your tickets are destroyed automatically when you log out.


ENVIRONMENT
~~~~~~~~~~~~~

*kdestroy* uses the following environment variables:

     **KRB5CCNAME**
          Location of the default Kerberos 5 credentials (ticket)
          cache, in the form *type*:*residual*.  If no type prefix is
          present, the **FILE** type is assumed.  The type of the
          default cache may determine the availability of a cache
          collection; for instance, a default cache of type **DIR**
          causes caches within the directory to be present in the
          collection.


FILES
~~~~~~~~~~~~~

/tmp/krb5cc_[uid]  - Default location of Kerberos 5 credentials cache ([*uid*] is the decimal UID of the user).


SEE ALSO
~~~~~~~~~

kinit(1), klist(1), krb5(3)


BUGS
~~~~~

Only the tickets in the specified credentials cache are destroyed. 
Separate ticket caches are used to hold root instance and password changing tickets.
These should probably be destroyed too, or all of a user's tickets kept in a single credentials cache.

