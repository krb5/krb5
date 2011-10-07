.. _kproplog(8):

kproplog
===========


SYNOPSIS
------------

**kproplog** [**-h**] [**-e** *num*] [-v]

DESCRIPTION
------------

The *kproplog* command displays the contents of the Kerberos principal update log to standard output.  
It can be used to keep track of the incremental updates to the principal database, when enabled.  
The update log file contains the update log maintained by the *kadmind* process on the master KDC server and the *kpropd* process on the slave KDC servers.  
When updates occur, they are logged to this file.  
Subsequently any KDC slave configured for incremental updates will request the current data from the master KDC and update their *principal.ulog* file with any updates returned.

The *kproplog* command can only be run on a KDC server by someone with privileges comparable to the superuser.
It will display update entries for that server only.

If no options are specified, the summary of the update log is displayed.  
If invoked on the master, all of the update entries are also displayed.
When invoked on a slave KDC server, only a summary of the updates are displayed, which includes the serial number of the last update received and the associated time stamp of the last update.

OPTIONS
------------

       **-h**
             Display a summary of the update log. This information includes the database version number, state of the database, 
             the number of updates in the log, the time stamp of the first and last update, and the version number of the first and last update entry.

       **-e** *num*
             Display the last *num* update entries in the log.  This is useful when debugging synchronization between KDC servers.

       **-v**
             Display individual attributes per update.  An example of the output generated for one entry::

               Update Entry
                  Update serial # : 4
                  Update operation : Add
                  Update principal : test@EXAMPLE.COM
                  Update size : 424
                  Update committed : True
                  Update time stamp : Fri Feb 20 23:37:42 2004
                  Attributes changed : 6
                        Principal
                        Key data
                        Password last changed
                        Modifying principal
                        Modification time
                        TL data

SEE ALSO
------------

kpropd(8)

