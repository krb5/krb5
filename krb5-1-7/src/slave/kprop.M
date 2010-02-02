.\" slave/kprop.M
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
.TH KPROP 8
.SH NAME
kprop \- propagate a Kerberos V5 principal database to a slave server
.SH SYNOPSIS
.B kprop
[\fB\-r\fP \fIrealm\fP] [\fB\-f\fP \fIfile\fP] [\fB\-d\fP] [\fB\-P\fP
\fIport\fP] [\fB\-s\fP \fIkeytab\fP] 
.I slave_host
.br
.SH DESCRIPTION
.I kprop
is used to propagate a Kerberos V5 database dump file from the master
Kerberos server to a slave Kerberos server, which is specfied by
.IR slave_host .  
This is done by transmitting the dumped database file to the slave
server over an encrypted, secure channel.  The dump file must be created
by kdb5_util, and is normally KPROP_DEFAULT_FILE
(/usr/local/var/krb5kdc/slave_datatrans).
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
found; by default the dumped database file is KPROP_DEFAULT_FILE
(normally /usr/local/var/krb5kdc/slave_datatrans).
.TP
\fB\-P\fP \fIport\fP
specifies the port to use to contact the
.I kpropd
server on the remote host.
.TP
.B \-d
prints debugging information.
.TP
\fB\-s\fP \fIkeytab\fP
specifies the location of the keytab file.
.SH SEE ALSO
kpropd(8), kdb5_util(8), krb5kdc(8)
