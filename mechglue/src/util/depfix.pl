#!env perl -w
eval 'exec perl -S $0 ${1+"$@"}'
  if 0;
$0 =~ s/^.*?(\w+)[\.\w+]*$/$1/;

# Input: srctop thisdir srcdir buildtop libgccfilename stlibobjs

# Notes: myrelativedir is something like "lib/krb5/asn.1" or ".".
# stlibobjs will usually be empty, or include spaces.

# A typical set of inputs, produced with srcdir=.. at top level:
#
# SRCTOP = ../../../util/et/../..
# thisdir = util/et
# srcdir = ../../../util/et
# BUILDTOP = ../..
# libgcc file name = /usr/lib/gcc-lib/i386-redhat-linux/3.2.3/libgcc.a
# STLIBOBJS = error_message.o et_name.o com_err.o

my($SRCTOP,$thisdir,$srcdir,$BUILDTOP,$libgccpath,$STLIBOBJS) = @ARGV;

if (0) {
    print STDERR "SRCTOP = $SRCTOP\n";
    print STDERR "BUILDTOP = $BUILDTOP\n";
    print STDERR "STLIBOBJS = $STLIBOBJS\n";
}

$libgccincdir = $libgccpath;
$libgccincdir =~ s,libgcc\.[^ ]*$,include,;
$libgccincdir = quotemeta($libgccincdir);
#$srcdirpat = quotemeta($srcdir);

sub my_qm {
    my($x) = @_;
    $x = quotemeta($x);
    $x =~ s,\\/,/,g;
    return $x;
}

sub strrep {
    my($old,$new,$s) = @_;
    my($l) = "strrep('$old','$new','$s')";
    my($out) = "";
    while ($s ne "") {
	my($i) = index($s, $old);
	if ($i == -1) {
	    $out .= $s;
	    $s = "";
	} else {
	    $out .= substr($s, 0, $i) . $new;
	    if (length($s) > $i + length($old)) {
		$s = substr($s, $i + length($old));
	    } else {
		$s = "";
	    }
	}
    }
#    print STDERR "$l = '$out'\n";
    return $out;
}

sub do_subs {
    local($_) = @_;
    s,\\$, \\,g; s, + \\$, \\,g;
    s,//+,/,g; s, \./, ,g;
    if ($STLIBOBJS ne "") {
	# Only care about the additional prefixes if we're building
	# shared libraries.
	s,^([a-zA-Z0-9_\-]*)\.o:,$1.so $1.po \$(OUTPRE)$1.\$(OBJEXT):,;
    } else {
	s,^([a-zA-Z0-9_\-]*)\.o:,\$(OUTPRE)$1.\$(OBJEXT):,;
    }
    # Drop GCC include files, they're basically system headers.
    s,$libgccincdir/[^ ]* ,,go;
    s,$libgccincdir/[^ ]*$,,go;
    # Recognize $(SRCTOP) and variants.
    my($srct) = $SRCTOP . "/";
    $_ = strrep(" $srct", " \$(SRCTOP)/", $_);
#    s, $pat, \$(SRCTOP)/,go;
    while ($srct =~ m,/[a-z][a-zA-Z0-9_.\-]*/\.\./,) {
	$srct =~ s,/[a-z][a-zA-Z0-9_.\-]*/\.\./,/,;
	$_ = strrep(" $srct", " \$(SRCTOP)/", $_);
    }
    # Now try to produce pathnames relative to $(srcdir).
    if ($thisdir eq ".") {
	# blah
    } else {
	my($pat) = " \$(SRCTOP)/$thisdir/";
	my($out) = " \$(srcdir)/";
	$_ = strrep($pat, $out, $_);
	while ($pat =~ m,/[a-z][a-zA-Z0-9_.\-]*/$,) {
	    $pat =~ s,/[a-z][a-zA-Z0-9_.\-]*/$,/,;
	    $out .= "../";
	    if ($pat ne " \$(SRCTOP)/") {
		$_ = strrep($pat, $out, $_);
	    }
	}
    }
    # Now substitute for BUILDTOP:
    $_ = strrep(" $BUILDTOP/", " \$(BUILDTOP)/", $_);
    return $_;
}

sub do_subs_2 {
    local($_) = @_;
    # Add a trailing space.
    s/$/ /;
    # Remove excess spaces.
    s/  */ /g;
    # Delete Tcl-specific headers.
    s;/[^ ]*/tcl\.h ;;g;
    s;/[^ ]*/tclDecls\.h ;;g;
    s;/[^ ]*/tclPlatDecls\.h ;;g;
    # Delete system-specific or compiler-specific files.
    s;/os/usr/include/[^ ]* ;;g;
    s;/usr/include/[^ ]* ;;g;
    s;/usr/lib/[^ ]* ;;g;
    # Remove foo/../ sequences.
    while (m/\/[a-z][a-z0-9_.\-]*\/\.\.\//) {
	s//\//g;
    }
    # Use VPATH.
    s;\$\(srcdir\)/([^ /]* );$1;g;

    # Allow override of some util dependencies in case local tools are used.
    s;\$\(BUILDTOP\)/include/com_err.h ;\$(COM_ERR_DEPS) ;g;
    s;\$\(BUILDTOP\)/include/ss/ss.h \$\(BUILDTOP\)/include/ss/ss_err.h ;\$(SS_DEPS) ;g;
    s;\$\(BUILDTOP\)/include/db.h \$\(BUILDTOP\)/include/db-config.h ;\$(DB_DEPS) ;g;

    $_ = &uniquify($_);

    # Some krb4 dependencies should only be present if building with krb4
    # enabled.
    s;\$\(BUILDTOP\)/include/kerberosIV/krb_err.h ;\$(KRB_ERR_H_DEP) ;g;

    # Delete trailing whitespace.
    s; *$;;g;

    return $_;
}

sub uniquify {
    # Apparently some versions of gcc -- like
    # "gcc version 3.4.4 20050721 (Red Hat 3.4.4-2)"
    # -- will sometimes emit duplicate header file names.
    local($_) = @_;
    my(@words) = split " ", $_;
    my($w);
    my($result) = "";
    my(%seen);
    undef %seen;
    foreach $w (@words) {
	next if defined($seen{$w});
	$seen{$w} = 1;
	if ($result ne "") { $result .= " "; }
	$result .= $w;
    }
    return $result . " ";
}

sub split_lines {
    local($_) = @_;
    s/(.{50}[^ ]*) /$1 \\\n  /g;
    return $_ . "\n";
}

print <<EOH ;
# +++ Dependency line eater +++
# 
# Makefile dependencies follow.  This must be the last section in
# the Makefile.in file
#
EOH
my $buf = '';
while (<STDIN>) {
    # Strip newline.
    chop;
    # Do directory-specific path substitutions on each filename read.
    $_ = &do_subs($_);
    if (m/\\$/) {
	chop;
	$buf .= $_;
    } else {
	$buf = &do_subs_2($buf . $_);
	print &split_lines($buf);
	$buf = '';
    }
}
exit 0;
