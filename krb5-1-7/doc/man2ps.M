.TH MAN2PS 1
.SH NAME
man2ps \- create individual PostScript files for each page of a man page
.SH SYNOPSIS
.B man2ps
.I file
[\fIfile2\fP [\fI...\fP]]
.SH DESCRIPTION
.B man2ps
is a bourne shell script that turns a man page into a set of PostScript
files, for inclusion in a document.
.B man2ps
converts the man page to a PostScript file using
.IR groff (1), 
and then uses the
.IR csplit (1)
command to split the file into individual pages.
.B man2ps
inserts the PostScript command:
.sp
.nf
.in +.5i
\&0.85 dup scale
.in -.5i
.fi
.sp
at the beginning of each page, so that the pages will fit onto an
8.5"x11" page.
.PP
The files created by
.B man2ps
have the same name as the command, with a sequential number and the
string ".ps" appended.  For example, running
.B man2ps
on the file "kinit.M" would produce the PostScript files "kinit1.ps",
"kinit2.ps", ...
.SH SEE ALSO
troff(1), csplit(1)
.SH BUGS
.B man2ps
requires the user to have
.I groff
and either
.I csplit
or
.I gcsplit
in her path.
.SH AUTHORS
.B man2ps
was written by Jeff Bigler at Cygnus Support and Theodore Ts'o at MIT.
