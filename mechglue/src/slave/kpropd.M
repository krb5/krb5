.\" slave/kpropd.M
.\"
.\" Copyright 1992 by the Massachusetts Institute of Technology.
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
.TH KPROPD 8
.SH NAME
kpropd \- Kerberos V5 slave KDC update server
.SH SYNOPSIS
.B kpropd
[
.B \-r
.I realm
] [
.B \-f
.I slave_dumpfile
] [
.B \-F
.I principal_database
] [
.B \-p
.I kdb5_util_prog
] [
.B \-d
] [
.B \-S
] [
.B \-P
.I port
]
.br
.SH DESCRIPTION
.I kpropd 
is the server which accepts connections from the 
.IR kprop (8)
program.  
.I kpropd 
accepts the dumped KDC database and places it in a file, and then runs 
.IR kdb5_util (8)
to load the dumped database into the active database which is used by 
.IR krb5kdc (8).
Thus, the master Kerberos server can use 
.IR kprop (8)
to propagate its database to the slave slavers.  Upon a successful download 
of the KDC database file, the slave Kerberos server will have an
up-to-date KDC database. 
.PP
Normally, kpropd is invoked out of 
.I inetd(8).  
This is done by adding a line to the inetd.conf file which looks like
this:

kprop	stream	tcp	nowait	root	/usr/local/sbin/kpropd	kpropd

However, kpropd can also run as a standalone deamon, if the
.B \-S
option is turned on.  This is done for debugging purposes, or if for
some reason the system administrator just doesn't want to run it out of
.IR inetd (8).
.SH OPTIONS
.TP
\fB\-r\fP \fIrealm\fP
specifies the realm of the master server; by default the realm returned
by
.IR krb5_default_local_realm (3)
is used.
.TP
\fB\-f\fP \fIfile\fP
specifies the filename where the dumped principal database file is to be
stored; by default the dumped database file is KPROPD_DEFAULT_FILE
(normally /usr/local/var/krb5kdc/from_master).
.TP
.B \-p
allows the user to specify the pathname to the
.IR kdb5_util (8)
program; by default the pathname used is KPROPD_DEFAULT_KDB5_UTIL
(normally /usr/local/sbin/kdb5_util).
.TP
.B \-S
turn on standalone mode.  Normally, kpropd is invoked out of
.IR inetd (8)
so it expects a network connection to be passed to it from
.I inetd (8).
If the 
.B \-S 
option is specified, kpropd will put itself into the background, and
wait for connections to the KPROP_SERVICE port (normally krb5_prop).
.TP
.B \-d
turn on debug mode.  In this mode, if the
.B \-S 
option is selected, 
.I kpropd
will not detach itself from the current job and run in the background.
Instead, it will run in the foreground and print out debugging messages
during the database propagation.
.TP
.B \-P
allow for an alternate port number for
.I kpropd
to listen on. This is only useful if the program is run in standalone
mode.
.SH FILES
.TP "\w'kpropd.acl\ \ 'u"
kpropd.acl
Access file for
.BR kpropd .
Each entry is a line containing the principal of a host from which the
local machine will allow Kerberos database propagation via kprop.
.SH SEE ALSO
kprop(8), kdb5_util(8), krb5kdc(8), inetd(8)
