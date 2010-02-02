.\" sccsid = "@(#)  man2html.1  1.2  08/12/97"
.\"
.\" ================================================
.\" ARGUMENT MACRO:		.Ar "arg" [B]
.de Ar
.ie \\$2B  \%\fB\\$1\fR
.el              \%\fI\\$1\fR
..
.\" ================================================
.\" BRACKETED ARGUMENT MACRO:	.Br "arg" [B]
.de Br
.ie \\$2B  \%[\|\fB\\$1\fR\|]
.el              \%[\|\fI\\$1\fR\|]
..
.\" ================================================
.\" OPTION FLAG MACRO		.Of -x [arg]
.de Of
.ie \\n(.$==1      \%[\|\fB\\$1\fR\|]
.el .if \\n(.$==2  \%[\|\fB\\$1\fR\0\fI\fI\\$2\fR\|]
..
.\" ================================================
.\" SYNOPSIS START MACRO
.de Ss				.Ss name
.na
.nr aA \w\\$1\\0u
.in +\\n(aAu
'ti -\\n(aAu
.ta  \\n(aAu
\&\fB\\$1\fR\t\c
..
.\" ================================================
.\" SYNOPSIS END MACRO
.de Se				.Se
.ad
.in
..
.\" ================================================
.\"
.\"
.TH MAN2HTML 1 "97/08/12"
.SH NAME
.na
man2html \- convert UNIX nroff(1) manual pages to HTML format
.SH SYNOPSIS
.na
.Ss man2html
.Of -bare
.Of -belem name
.Of -botm lines
.Of -cgiurl string
.Of -cgiurlexp expr
.Of -compress
.Of -headmap mapfile
.Of -help
.Of -k
.Of -leftm chars
.Of -nodepage
.Of -noheads
.Of -pgsize lines
.Of -seealso
.Of -solaris
.Of -sun
.Of -title string
.Of -topm lines
.Of -uelem name
.Se
.sp 2
Typical Usage:
.sp
.Ss man2html
.Of -options
.BI "\0<\0" infile
.BI "\0\0>\0" outfile
.Se
.sp
.B man
.I topic
.B | man2html
.Of -options
.BI "\0>\0" outfile
.\"
.SH DESCRIPTION
.na
The
.B man2html
filter reads formatted nroff text from standard input
.RI ( stdin )
and writes a \s-1HTML\s+1 document to standard output
.RI ( stdout ).
.LP
The formatted nroff output is surrounded with
.B \s-1<PRE>\s+1
tags with the following exceptions/additions:
.RS 4n
.LP
.na
'ti -2n
'ta  2n
\(bu	Section heads are wrapped in \s-1HTML\s+1
.I header
tags.
See the
.B "\s-1SECTION\ HEAD\ MAP\ FILE\s+1"
section below for additional information.
The
.B \%-noheads
option can be used to disable this feature.
.ad
.LP
.na
'ti -2n
'ta  2n
\(bu	Bold words designated by a \%"<char><bs><char>"
sequences are wrapped in
.B \s-1<B>\s+1
tags (or the element specified via the
.B \%-belem
option).
.ad
.LP
.na
'ti -2n
'ta  2n
\(bu	Underlined words designated by a \%"_<bs><char>"
sequences are wrapped in
.B \s-1<I>\s+1
tags (or the element specified via the
.B \%-uelem
option).
.ad
.RE
.SH OPTIONS
.na
.TP 0.5i
.B -bare
This option will eliminate \s-1HTML\s+1
.B \s-1<HEAD>\s+1
and
.B \s-1<BODY>\s+1
tags from the output.
This is useful when you wish to incorporate the output into another
\s-1HTML\s+1 document.
.TP 0.5i 
.BI -belem\0 name
Use
.I name
as the name of the element to wrap overstriken characters.
The default is \fBB\fR.
.TP 0.5i 
.BI -botm\0 lines
The
.I lines
argument specifies the number of lines representing the bottom
margin of the formatted nroff input.
The line count includes any running footers.
The default value is 7.
.TP 0.5i
.BI -cgiurl\0 string
The
.I string
argument specifies a template \s-1URL\s+1 for creating links to other manpages.
See the
.B "\s-1LINKING\ TO\ OTHER\ MANPAGES\s+1"
section below for additional information.
.TP 0.5i
.BI -cgiurlexp\0 expr
The
.I expr
argument specifies a Perl expression evaluting to a \s-1URL\s+1 for
creating links to other manpages.
See the
.B "\s-1LINKING\ TO\ OTHER\ MANPAGES\s+1"
section below for additional information.
.TP 0.5i
.B -compress
Compress consecutive blank lines into a single line.
.TP 0.5i
.BI -headmap\0 mapfile
The
.I mapfile
argument is read to determine which \s-1HTML\s+1
header tags are to be used for various section heading in the manpage.
See the
.B "\s-1SECTION\ HEAD\ MAP\ FILE\s+1"
section below for information on the format of the map file.
.TP 0.5i
.B -help
Print out a short usage message and then exit immediately.
.TP 0.5i
.B -k
Process input resulting from a manpage keyword search
.RB ( "man\ -k" ).
See the
.B "\s-1KEYWORD\ SEARCH\s+1"
section below for additional information.
.TP 0.5i
.BI -leftm\0 chars
The
.I chars
argument specifies the width of the number of characters making
up the left margin of the formatted nroff input.
The default value is 0.
.TP 0.5i
.B -nodepage
By default,
.B man2html
merges multi-page formatted nroff into a single page.
This option may be used to disable depagination, causing
running headers and footers in the formatted nroff input
to be carried over into the \s-1HTML\s+1 output.
.TP 0.5i
.B -noheads
By default,
.B man2html
wraps section heads in \s-1HTML\s+1
header tags.
See the
.B "\s-1SECTION\ HEAD\ MAP\ FILE\s+1"
section below for additional information.
This option may be specified to disabled this feature.
.TP 0.5i
.BI -pgsize\0 lines
The
.I lines
argument specifies the number of lines making up the page size (length)
of the formatted nroff input.
The default value is 66.
.TP 0.5i
.B -seealso
If the
.B -cgiurl
option has been specified, then this option restricts the
creation of links to other manual pages to the
.B "\%\s-1SEE\ ALSO\s+1"
section only.
.TP 0.5i
.B -solaris
If the
.B -k
option has been specified, then this option modifies its operation
to process the alternate manual page keyword search format produced
by the
.BR man (1)
utility on systems running
.IR Solaris .
See the
.B "\s-1KEYWORD\ SEARCH\s+1"
section below for additional information.
.TP 0.5i
.B -sun
Do not require a section head to have bold overstriking in the
formatted nroff input.
The option is called
.B \%sun
because it was on a Sun workstation that section heads in
manpages were found to not be overstruck.
.TP 0.5i
.BI -title\0 string
By default,
.B man2html
does not generate a \s-1HTML\s+1 title
.RB ( \s-1<TITLE>\s+1 ).
This option sets the title of the \s-1HTML\s+1 output to the specified
.IR string .
.TP 0.5i
.BI -topm\0 lines
The
.I lines
argument specifies number number of lines representing the
top margin of the formatted nroff input.
The line count includes any running headers.
The default value is 7.
.TP 0.5i 
.BI -uelem\0 name
Use
.I name
as the name of the element to wrap underscored characters.
The default is \fBI\fR.
.\"
.SH "SECTION HEAD MAP FILE"
.na
.LP
The
.B \%-headmap
option may be used to customize which \s-1HTML\s+1 header tags,
.BR "\s-1<H1>\s+1 ... \s-1<H6>\s+1" ,
are used in manpage section headings.
Normally,
.B man2html
treats lines that are flush to the left margin
.RB ( -leftm ),
and contain overstriking (overstrike check is canceled with the
.B -sun
option), as section heads.
However, you can augment/override what \s-1HTML\s+1 header tags are used for
any given section head.
.LP
In order to write a section head map file, you will need to know about
.BR perl (1)
associative arrays.
You do not need to be an expert in
.B perl
to write a map file, however, having knowledge of
.B perl
allows you to be more clever.
.\"
.SS "Augmenting the Default Map" 
.LP
To add to the default mapping defined by
.BR man2html ,
your map file will contain lines with the following syntax:
.sp
.if t .RS 4n
.B "$SectionHead{'<section head text>'} = '<html header tag>';"
.if t .RE
.sp
where
.IP "\fB\%<section\ head\ text>\fR"
is the text of the manpage section head.
For example:
.B  \s-1SYNOPSIS\s+1
or
.BR \s-1DESCRIPTION\s+1 .
.IP "\fB\%<html\ header\ tag>\fR"
is the \s-1HTML\s+1 header tag to wrap the section head in.
Legal values are:
.BR \s-1<H1>\s+1 ,
.BR \s-1<H2>\s+1 ,
.BR \s-1<H3>\s+1 ,
.BR \s-1<H4>\s+1 ,
.BR \s-1<H5>\s+1 ,
.BR \s-1<H6>\s+1 .
.SS "Overriding the Default Map"
To override the default mapping with your own, then your map file will
have the following syntax:
.sp
.RS 4n
.ft B
.nf
.ne 6v
%SectionHead = (
         \&'<section head text>', '<html header tag>',
         \&'<section head text>', '<html header tag>',
         \&# ... More section head/tag pairs
         \&'<section head text>', '<html header tag>',
);
.fi
.ft
.RE
.SS "The Default Map"
.LP
As of this writing, this is the default map used by
.BR man2html :
.RS 4n
.sp
.ft C
.nf
.ne 29v
%SectionHead = (
.ps -1
    \&'\\S.*OPTIONS.*'             => '<H2>',
    \&'AUTHORS?'                  => '<H2>',
    \&'BUGS'                      => '<H2>',
    \&'COMPATIBILITY'             => '<H2>',
    \&'DEPENDENCIES'              => '<H2>',
    \&'DESCRIPTION'               => '<H2>',
    \&'DIAGNOSTICS'               => '<H2>',
    \&'ENVIRONMENT'               => '<H2>',
    \&'ERRORS'                    => '<H2>',
    \&'EXAMPLES'                  => '<H2>',
    \&'EXTERNAL INFLUENCES'       => '<H2>',
    \&'FILES'                     => '<H2>',
    \&'LIMITATIONS'               => '<H2>',
    \&'NAME'                      => '<H2>',
    \&'NOTES?'                    => '<H2>',
    \&'OPTIONS'                   => '<H2>',
    \&'REFERENCES'                => '<H2>',
    \&'RETURN VALUE'              => '<H2>',
    \&'SECTION.*:'                => '<H2>',
    \&'SEE ALSO'                  => '<H2>',
    \&'STANDARDS CONFORMANCE'     => '<H2>',
    \&'STYLE CONVENTION'          => '<H2>',
    \&'SYNOPSIS'                  => '<H2>',
    \&'SYNTAX'                    => '<H2>',
    \&'WARNINGS'                  => '<H2>',
    \&'\\s+Section.*:'             => '<H3>',
.ps +1
);
$HeadFallback = '\s-1<H2>\s+1';  # Fallback tag if above is not found.
.fi
.ft
.RE
.LP
Check the
.B perl
source code of
.B man2html
for the latest default mapping.
.LP 
You can reassign the
.B \%$HeadFallback
variable to a different value if you choose.
This value is used as the header tag of a section head if
no matches are found in the \%\fB%SectionHead\fR map.
.SS "Using Regular Expressions in the Map File"
.LP
You may have noticed unusual characters in the default map file, like
"\\s" or "*".
The
.B man2html
utility actual treats the
.B "\%<section\ head\ text>"
as a
.B perl
regular expression.
If you are comfortable with
.B perl
regular expressions, then you have their full power to use
in your map file.
.LP
.I Caution:
The
.B man2html
utility already anchors the regular expression to the beginning of the
line with left margin spacing specified by the
.B \%-leftm
option.
Therefore, do not use the `\fB\fR^' character to anchor your regular
expression to the beginning.
However, you may end your expression with a `\fB$\fR' to anchor it to
the end of the line.
.LP 
Since the
.B "\%<section\ head\ text>"
is actually a regular expression, you will have to be careful of
special characters if you want them to be treated literally.
Any of the characters
.RB ` "[ ] ( ) . ^ { } $ * ? + \\ |" '
should be escaped by prefixing them by the
\&`\fB\\\fR' character if you want
.B perl
to treat them "as is".
.LP
.I Caution:
One should use single quotes instead of double quotes to delimit
.BR "\%<section\ head\ text>" .
This will preserve any `\fB\\\fR' characters for character escaping
or when the `\fB\\\fR' is used for special
.B perl
character matching sequences (e.g.,  \fB\\s\fR, \fB\\w\fR, \fB\\S\fR).
.SS "Other Tid-bits on the Map File"
.LP
Comments can be inserted in the map file by using the '\fB#\fR'
character.
Anything after, and including, the '\fB#\fR' character is ignored,
up to the end of line.
.LP 
You might be thinking that the above is quite-a-bit-of-stuff just for
doing manpage section heads.
However, you will be surprised how much better the \s-1HTML\s+1 output looks
with header tags, even though, everything else is in a
.B \s-1<PRE>\s+1
tag.
.\"
.SH "LINKING TO OTHER MANPAGES"
.na
.LP 
The
.B man2html
utility allows the ability to link to other manpage references.
If the
.B \%-cgiurl
option is specified,
.B man2html
will create anchors that link to other manpages.
.LP 
The \s-1URL\s+1 entered with the
.B \%-cgiurl
option is actually a template that determines the actual \s-1URL\s+1 used to
link to other manpages.
The following variables are defined during run time that may be used in
the template string:
.sp
.RS 4n
.IP \fB$title\fR
The title of the manual page referenced.
.IP \fB$section\fR
The section number of the manual page referenced.
.IP \fB$subsection\fR
The subsection of the manual page referenced.
.RE
.LP
Any other text in the template is preserved "as is".
.LP
.I Caution:
The
.B man2html
utility evaluates the template string as a
.B perl
string expression.
Therefore, one might need to surround the variable names with
\&'\fB{\|}\fR' (e.g.,
.BR ${\|title\|}\| )
so that
.B man2html
properly recognizes the variable.
.LP
.I Note:
If a \s-1CGI\s+1 program calling
.B man2html
is actually a shell script or a
.B perl
program, make sure to properly escape the '\fB$\fR' character
in the \s-1URL\s+1 template to avoid variable interpolation by the \s-1CGI\s+1
program.
.LP
Normally, the \s-1URL\s+1 calls a \s-1CGI\s+1 program (hence the option name),
but the \s-1URL\s+1 can easily link to statically converted documents.
.SS "Example1:"
.LP 
The following template string is specified to call a \s-1CGI\s+1 program to
retrieve the appropriate manpage linked to:
.LP
.nf
.B "/cgi-bin/man.cgi?section=${section}${subsection}&topic=${title}"
.fi
.LP 
If the
.BR ls (1)
manpage is referenced in the
.B "SEE ALSO"
section, the above template will translate to the following \s-1URL\s+1:
.LP
.B "/cgi-bin/man.cgi?section=1&topic=ls"
.LP 
The actual \s-1HTML\s+1 markup will look like the following:
.LP
\fB<A\ HREF="/cgi-bin/man.cgi?section=1&topic=ls">ls(1)</A>\fR
.SS "Example2:"
.LP 
The following template string is specified to retrieve pre-converted
manpages:
.LP
.B "http://foo.org/man$section/$title.$section$subsection.html"
.LP 
If the
.BR mount (1M)
manpage is referenced, the above template will translate to the
following \s-1URL\s+1:
.LP
.B "http://foo.org/man1/mount.1M.html"
.LP 
The actual \s-1HTML\s+1 markup will look like the following:
.LP
\fB<A HREF="http://foo.org/man1/mount.1M.html">mount(1M)</A>\fR
.SS "-cgiurlexp"
The option
.B \%-cgiurlexp
is a more general form of the
.B \%-cgiurl
option.
.B \%-cgiurlexp
allows one to specify a general Perl expression.  For example:
.LP
\fB$title=~/^db_/i?"$title.html":"/cgi-bin/man?$title+$section"\fR
.LP
A
.B \%-cgiurl
.I string
can be expressed as follows with \fB-cgiurlexp\fR:
.LP
\fBreturn "\fIstring\fB"\fR
.\"
.SH "KEYWORD SEARCH"
.na
.LP
The
.B man2html
utility has the ability to process keyword search output generated
by the \%\fBman\ -k\fR or \%\fBapropos\fR commands, through the
use of the
.B -k
option.
The
.B man2html
utility will generate an \s-1HTML\s+1 document of the keyword search input
having the following format:
.RS 4n 
.LP
.na
'ti -2n
'ta  2n
\(bu	All manpage references are listed by section.
.ad
.LP
.na
'ti -2n
'ta  2n
\(bu	Within each section listing, the manpage references
are sorted alphabetically (case-sensitive) in a
.B \s-1<DL>\s+1
tag.
The manpage references are listed in the
.B \s-1<DT>\s+1
section, and the summary text is listed in the
.B \s-1<DD>\s+1
section.
.ad
.LP
.na
'ti -2n
'ta  2n
\(bu	Each manpage reference listed is a hyperlink to the
actual manpage as specified by the
.B \%-cgiurl
option.
.ad
.RE
.LP 
.na
This ability to process keyword searches gives nice added functionality
to a \s-1WWW\s+1 forms interface to
.BR man (1).
Even if you have statically converted manpages to \s-1HTML\s+1 via another
man->\s-1HTML\s+1 program, you can use
.B man2html
and "\fBman\ -k\fR" to provide keyword search capabilities easily for
your \s-1HTML\s+1 manpages.
.SS "Processing Keyword Search Results"
.na
.LP 
Unfortunately, there is no standard controlling the format of keyword
search results.
The
.B man2html
utility tries it best to handle all the variations.
However, the keyword search results generated by the
.I Solaris
operating system is different enough from other systems that a
special command-line option
.RB ( -solaris )
must be specified to handle its output.
.SS "Example of raw Solaris-type keyword search results:"
.LP
.ft C
.nf
.ne 10v
strcpy        strcpy (9f)  - copy a string from one location to another.
strcpy        string (3c)  - string operations
strncpy       strcpy (9f)  - copy a string from one location to another.
strncpy       string (3c)  - string operations
.fi
.ft
.LP 
If keyword search results on your systems appear in the following format:
.LP
.RS 4n
.B "<topic>  <actual_manpage> (#) - Description"
.RE
.LP
then you need to specify the
.B \%-solaris
option in addition to the
.B -k
option.
.SH "ADDITIONAL NOTES"
.na
.LP
Different systems format manpages differently.
Here is a list of recommended command-line options for certain systems:
.RS 4n
.LP
.ta 1i
.nf
.ne 3v
\fBConvex\fR:	<defaults should be okay>
\fBHP\fR:	\fB-leftm 1 -topm 8\fR
\fBSun\fR:	\fB-sun\fR (and \fB-solaris\fR when using \fB-k\fR)
.fi
.RE
.LP
Some line spacing gets lost in the formatted nroff since the
spacing would occur in the middle of a page break.
This can cause text to be merged that shouldn't be merged when
.B man2html
depaginates the text.
To avoid this problem,
.B man2html
keeps track of the margin indent right before and after a page break.
If the margin width of the line after the page break is less than the
line before the page break, then
.B man2html
inserts a blank line in the \s-1HTML\s+1 output.
.LP 
A manpage cross-reference is detected by the following pseudo expression:
\%\fB[A-z.-+_]+([0-9][A-z]?)\fR
.LP
The
.B man2html
utility only recognizes lines with "\fB - \fR" (the normal separator
between manpage references and summary text) while in keyword
search mode.
.LP 
The
.B man2html
utility can be hooked in a \s-1CGI\s+1 script/program to convert manpages
on the fly.
This is the reason for the
.B \%-cgiurl
option.
.SH LIMITATIONS
.na
.LP 
The order that section head mapping is searched is not defined.
Therefore, if two or more
.B "\%<section\ head\ text>"
can match a give manpage section, there is no way to determine
which map tag is chosen.
.LP 
If
.B \%-seealso
is specified, all xrefs are detected after the
.B "\%SEE\ ALSO"
heading.
In other words, sections after
.B "\%SEE\ ALSO"
may contain hyperlinked xrefs.
.SH BUGS
.na
.LP 
Text that is flush to the left margin, but is not actually a
section head, can be mistaken for a section head.
This mistake is more likely when the
.B \%-sun
option is in affect.
.SH VERSION
.na
This documentation describes
.B man2html
version 3.0.1
.SH "SEE ALSO"
.na
.BR man (1),
.BR nroff (1),
.BR perl (1)
.LP
.I http://www.oac.uci.edu/indiv/ehood/man2html.html
.SH AUTHOR
.LP
.B Earl Hood
.br
.I ehood@medusa.acs.uci.edu
.\"
.SH "ERRORS AND OMISSIONS"
.na
Troff version of this document initially created for version 2.1.0
by C. Jeffery Small
.RI ( jeff@cjsa.com )
by copying, reformatting, rearranging and partially rewriting
the contents of the ascii text file
.BR doc/man2html.txt .
