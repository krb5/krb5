.\"
.\" (c) Copyright 1994 HEWLETT-PACKARD COMPANY
.\" 
.\" To anyone who acknowledges that this file is provided 
.\" "AS IS" without any express or implied warranty:
.\" permission to use, copy, modify, and distribute this 
.\" file for any purpose is hereby granted without fee, 
.\" provided that the above copyright notice and this 
.\" notice appears in all copies, and that the name of 
.\" Hewlett-Packard Company not be used in advertising or 
.\" publicity pertaining to distribution of the software 
.\" without specific, written prior permission.  Hewlett-
.\" Packard Company makes no representations about the 
.\" suitability of this software for any purpose.
.\"
.\" $Id
.\"
.TH mailquery 1
.SH NAME
mailquery \- queries a pop server about how much mail is available
.SH SYNTAX
.B mailquery
[-\fId\fR\|]
[-\fIv\fR\|]
[\fI user\fR[@\fIhost\fR\|]]
.SH DESCRIPTION
The
.PN mailquery 
command queries a POP server for information about how much mail a user
has.  The program will exit with status = 0 if there is mail, and with
status = 1 if there is no mail.  The -v flag can be used to get a more 
verbose report.  The -d flag can be used to turn on debugging output
in the pop library code.  The pop server can be specified either by
setting the environment variable MAILHOST, or on the command line.
If no user is specified, user is set to the person who ran the program.
.SH OPTIONS

.SH BUGS/LIMITATIONS

.SH SEE ALSO
popper(8)
