.. _incr_db_prop_label:



Incremental database propagation
====================================

.. note:: This document was copied from **Kerberos V5 Installation Guide** with minor changes. Currently it is under review. Please, send your feedback, corrections and additions to krb5-bugs@mit.edu. Your contribution is greatly appreciated.

Overview
----------

At some very large sites, dumping and transmitting the database can take more time than is desirable for changes to propagate from the master KDC to the slave KDCs. The incremental propagation support added in the 1.7 release is intended to address this.

With incremental propagation enabled, all programs on the master KDC that change the database also write information about the changes to an "update log" file, maintained as a circular buffer of a certain size. A process on each slave KDC connects to a service on the master KDC (currently implmented in the kadmind server) and periodically requests the changes that have been made since the last check. By default, this check is done every two minutes. If the database has just been modified in the previous several seconds (currently the threshold is hard-coded at 10 seconds), the slave will not retrieve updates, but instead will pause and try again soon after. This reduces the likelihood that incremental update queries will cause delays for an administrator trying to make a bunch of changes to the database at the same time.

Incremental propagation uses the following entries in the per-realm data in the KDC config file (See :ref:`kdc.conf`):

====================== =============== ===========================================
iprop_enable           *boolean*       If *true*, then incremental propagation is enabled, and (as noted below) normal kprop propagation is disabled. The default is *false*.
iprop_master_ulogsize  *integer*       Indicates the number of entries that should be retained in the update log. The default is 1000; the maximum number is 2500.
iprop_slave_poll       *time interval* Indicates how often the slave should poll the master KDC for changes to the database. The default is two minutes.
iprop_port             *integer*       Specifies the port number to be used for incremental propagation. This is required in both master and slave configuration files.
iprop_logfile          *file name*     Specifies where the update log file for the realm database is to be stored. The default is to use the *database_name* entry from the realms section of the config file :ref:`kdc.conf`, with *.ulog* appended. (NOTE: If database_name isn't specified in the realms section, perhaps because the LDAP database back end is being used, or the file name is specified in the *dbmodules* section, then the hard-coded default for *database_name* is used. Determination of the *iprop_logfile*  default value will not use values from the *dbmodules* section.) 
====================== =============== ===========================================

Both master and slave sides must have principals named *kiprop/hostname* (where *hostname* is, as usual, the lower-case, fully-qualified, canonical name for the host) registered and keys stored in the default keytab file (/etc/krb5.keytab).

On the master KDC side, the *kiprop/hostname* principal must be listed in the *kadmind* ACL file *kadm5.acl*, and given the *p* privilege (See :ref:`privileges_label`)

On the slave KDC side, *kpropd* should be run. When incremental propagation is enabled, it will connect to the *kadmind* on the master KDC and start requesting updates.

The normal *kprop* mechanism is disabled by the incremental propagation support. However, if the slave has been unable to fetch changes from the master KDC for too long (network problems, perhaps), the log on the master may wrap around and overwrite some of the updates that the slave has not yet retrieved. In this case, the slave will instruct the master KDC to dump the current database out to a file and invoke a one-time kprop propagation, with special options to also convey the point in the update log at which the slave should resume fetching incremental updates. Thus, all the keytab and ACL setup previously described for kprop propagation is still needed.

There are several known bugs and restrictions in the current implementation:

- The "call out to kprop" mechanism is a bit fragile; if the kprop propagation fails to connect for some reason, the process on the slave may hang waiting for it, and will need to be restarted.
- The master and slave must be able to initiate TCP connections in both directions, without an intervening NAT. They must also be able to communicate over IPv4, since MIT's kprop and RPC code does not currently support IPv6. 
- Sun/MIT Incremental Propagation Differences: 

Sun/MIT incremental propagation differences
----------------------------------------------

Sun donated the original code for supporting incremental database propagation to MIT. Some changes have been made in the MIT source tree that will be visible to administrators. (These notes are based on Sun's patches. Changes to Sun's implementation since then may not be reflected here.)

The Sun config file support looks for *sunw_dbprop_enable, sunw_dbprop_master_ulogsize,* and *sunw_dbprop_slave_poll*.

The incremental propagation service is implemented as an ONC RPC service. In the Sun implementation, the service is registered with *rpcbind* (also known as portmapper) and the client looks up the port number to contact. In the MIT implementation, where interaction with some modern versions of *rpcbind* doesn't always work well, the port number must be specified in the config file on both the master and slave sides.

The Sun implementation hard-codes pathnames in */var/krb5* for the update log and the per-slave kprop dump files. In the MIT implementation, the pathname for the update log is specified in the config file, and the per-slave dump files are stored in */usr/local/var/krb5kdc/slave_datatrans_hostname*. 
