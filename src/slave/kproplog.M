.\" slave/kprop.M
.\"
.\" Copyright 2008 by the Massachusetts Institute of Technology.
.\"
.\" Export of this software from the United States of America may
.\"   require a specific license from the United States Government.
.\"   It is the responsibility of any person or organization contemplating
.\"   export to obtain such a license before exporting.
.\" 
.\" WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
.\" distribute this software and its documentation for any purpose and
.\" without fee is hereby granted, provided that the above copyright
.\" notice appear in all copies and that both that copyright notice and
.\" this permission notice appear in supporting documentation, and that
.\" the name of M.I.T. not be used in advertising or publicity pertaining
.\" to distribution of the software without specific, written prior
.\" permission.  Furthermore if you modify this software you must label
.\" your software as modified software and not distribute it in such a
.\" fashion that it might be confused with the original M.I.T. software.
.\" M.I.T. makes no representations about the suitability of
.\" this software for any purpose.  It is provided "as is" without express
.\" or implied warranty.
.\" 
.\"
.\" Copyright (c) 2003, Sun Microsystems, Inc.  All Rights Reserved
.\"
.TH KPROPLOG 1
.SH NAME
kproplog \- display the contents of the Kerberos principal update log
.SH SYNOPSIS
.B kproplog
[\fB\-h\fP] [\fB\-e\fP \fInum\fP]
.br
.SH DESCRIPTION
The
.I kproplog
command displays the contents of the Kerberos principal update log to
standard output.  It can be used to keep track of the incremental
updates to the principal database, when enabled.  The update log
file contains the update log maintained by the
.I kadmind
process on the master KDC server and the kpropd process on the slave
KDC servers.  When updates occur, they are logged to this
file.  Subsequently any KDC slave configured for incremental updates
will request the current data from the master KDC and update their
.I principal.ulog
file with any updates returned.

The
.I kproplog
command can only be run on a KDC server by someone with privileges
comparable to the superuser.  It will display update entries for that
server only.

If no options are specified, the summary of the update log is
displayed.  If invoked on the master, all of the update entries are
also displayed.  When invoked on a slave KDC server, only a summary of
the updates are displayed, which includes the serial number of the
last update received and the associated time stamp of the last update.

.SH OPTIONS
.TP
\fB\-h\fP
Display a summary of the update log.  This information includes the
database version number, state of the database, the number of updates
in the log, the time stamp of the first and last update, and the
version number of the first and last update entry.
.TP
\fB\-e\fP \fInum\fP
Display the last
.I num
update entries in the log.  This is useful when debugging
synchronization between KDC servers.
.TP
\fB\-v\fP
Display individual attributes per update.
An example of the output generated for one entry:
.nf
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
.fi

.SH SEE ALSO
kpropd(8)
