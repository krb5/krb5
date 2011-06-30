Mac OS X configuration
=======================

To install Kerberos V5 on Mac OS X and Mac OS X Server, follow the directions for generic Unix-based OS's, except for the */etc/services* updates described above.

Mac OS X and Mac OS X Server use a database called NetInfo to store the contents of files normally found in */etc*. Instead of modifying */etc/services*, you should run the following commands to add the Kerberos service entries to NetInfo::

     $ niutil -create . /services/kerberos
     $ niutil -createprop . /services/kerberos name kerberos kdc
     $ niutil -createprop . /services/kerberos port 750
     $ niutil -createprop . /services/kerberos protocol tcp udp
     $ niutil -create . /services/krbupdate
     $ niutil -createprop . /services/krbupdate name krbupdate kreg
     $ niutil -createprop . /services/krbupdate port 760
     $ niutil -createprop . /services/krbupdate protocol tcp
     $ niutil -create . /services/kpasswd
     $ niutil -createprop . /services/kpasswd name kpasswd kpwd
     $ niutil -createprop . /services/kpasswd port 761
     $ niutil -createprop . /services/kpasswd protocol tcp
     $ niutil -create . /services/klogin
     $ niutil -createprop . /services/klogin port 543
     $ niutil -createprop . /services/klogin protocol tcp
     $ niutil -create . /services/eklogin
     $ niutil -createprop . /services/eklogin port 2105
     $ niutil -createprop . /services/eklogin protocol tcp
     $ niutil -create . /services/kshell
     $ niutil -createprop . /services/kshell name kshell krcmd
     $ niutil -createprop . /services/kshell port 544
     $ niutil -createprop . /services/kshell protocol tcp
     

In addition to adding services to NetInfo, you must also modify the resolver configuration in NetInfo so that the machine resolves its own hostname as a FQDN (fully qualified domain name). By default, Mac OS X and Mac OS X Server machines query NetInfo to resolve hostnames before falling back to DNS. Because NetInfo has an unqualified name for all the machines in the NetInfo database, the machine's own hostname will resolve to an unqualified name. Kerberos needs a FQDN to look up keys in the machine's keytab file.

Fortunately, you can change the lookupd caching order to query DNS first. Run the following NetInfo commands and reboot the machine::

     $ niutil -create . /locations/lookupd/hosts
     $ niutil -createprop . /locations/lookupd/hosts LookupOrder CacheAgent DNSAgent
      NIAgent NILAgent
     

Once you have rebooted, you can verify that the resolver now behaves correctly. Compile the Kerberos 5 distribution and run::

     $ cd .../src/tests/resolve
     $ ./resolve
     

This will tell you whether or not your machine returns FQDNs on name lookups. If the test still fails, you can also try turning off DNS caching. Run the following commands and reboot::

     $ niutil -create . /locations/lookupd/hosts
     $ niutil -createprop . /locations/lookupd/hosts LookupOrder DNSAgent
      CacheAgent NIAgent NILAgent
     

The remainder of the setup of a Mac OS X client machine or application server should be the same as for other UNIX-based systems.

------------

Feedback:

Please, provide your feedback or suggest a new topic at krb5-bugs@mit.edu?subject=Documentation___cl_install



