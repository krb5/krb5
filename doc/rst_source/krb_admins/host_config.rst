Host configuration
==================

All hosts running Kerberos software, whether they are clients,
application servers, or KDCs, can be configured using
:ref:`krb5.conf(5)`.  Here we describe some of the behavior changes
you might want to make.


.. _plugin_config:

Plugin module configuration
---------------------------

Many aspects of Kerberos behavior, such as client preauthentication
and KDC service location, can be modified through the use of plugin
modules.  For most of these behaviors, you can use the :ref:`plugins`
section of krb5.conf to register third-party modules, and to switch
off registered or built-in modules.

A plugin module takes the form of a Unix shared object
(``modname.so``) or Windows DLL (``modname.dll``).  If you have
installed a third-party plugin module and want to register it, you do
so using the **module** directive in the appropriate subsection of the
[plugins] section.  For example, to register a client
preauthentication plugin for one-time password authentication
installed at ``/path/to/otp.so``, you could write::

    [plugins]
        clpreauth = {
            module = /path/to/otp.so
        }

Many of the pluggable behaviors in MIT krb5 contain built-in modules
which can be switched off.  You can disable a built-in module (or one
you have registered) using the **disable** directive in the
appropriate subsection of the [plugins] section.  For example, to
disable the use of .k5identity files to select credential caches, you
could write::

    [plugins]
        ccselect = {
            disable = k5identity
        }

If you want to disable multiple modules, specify the **disable**
directive multiple times, giving one module to disable each time.

Alternatively, you can explicitly specify which modules you want to be
enabled for that behavior using the **enable_only** directive.  For
example, to make :ref:`kadmind(8)` check password quality using only a
module you have registered, and no other mechanism, you could write::

    [plugins]
        pwqual = {
            module = /path/to/mymodule.so
            enable_only = mymodule
        }

Again, if you want to specify multiple modules, specify the
**enable_only** directive multiple times, giving one module to enable
each time.

Some Kerberos interfaces use different mechanisms to register plugin
modules.


KDC location modules
~~~~~~~~~~~~~~~~~~~~

For historical reasons, modules to control how KDC servers are located
are registered simply by placing the shared object or DLL into the
"libkrb5" subdirectory of the krb5 plugin directory, which defaults to
``/usr/local/lib/krb5/plugins``.  For example, Samba's winbind krb5
locator plugin would be registered by placing its shared object in
``/usr/local/lib/krb5/plugins/libkrb5/winbind_krb5_locator.so``.


GSSAPI mechanism modules
~~~~~~~~~~~~~~~~~~~~~~~~

GSSAPI mechanism module are registered using the file
``/etc/gss/mech``.  Each line in this file has the form::

    oid  pathname  [options]

where *oid* is the object identifier of the GSSAPI mechanism to be
registered, *pathname* is a path to the module shared object or DLL,
and *options* (if present) are options provided to the plugin module,
surrounded in square brackets.


Configuration profile modules
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A configuration profile module replaces the information source for
:ref:`krb5.conf(5)` itself.  To use a profile module, begin krb5.conf
with the line::

    module PATHNAME:STRING

where *PATHNAME* is a path to the module shared object or DLL, and
*STRING* is a string to provide to the module.  The module will then
take over, and the rest of krb5.conf will be ignored.
