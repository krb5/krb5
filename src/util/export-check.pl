#
$0 =~ s/^.*?([\w.-]+)$/$1/;

# The real stuff.

# Args: exportlist libfoo.so

# This code assumes the GNU version of nm.
# For now, we'll only run it on GNU/Linux systems, so that's okay.

if ($#ARGV != 1) {
    die "usage: $0 exportfile libfoo.so\n";
}
my($exfile, $libfile) = @ARGV;

@missing = ();
open NM, "nm -Dg --defined-only $libfile |" || die "can't run nm on $libfile: $!";
open EXPORT, "< $exfile" || die "can't read $exfile: $!";

@export = <EXPORT>;
map chop, @export;
@export = sort @export;

@found = ();
while (<NM>) {
    chop;
    s/^[0-9a-fA-F]+ +//;
    next if /^A /;
    if (!/^[TDRB] /) {
	unlink $libfile;
	die "not sure what to do with '$_'";
    }
    s/^[TDRB] +//;
    push @found, $_;
}
@found = sort @found;
while ($#export >= 0 && $#found >= 0) {
    if ($export[0] eq $found[0]) {
#	print "ok $export[0]\n";
	shift @export;
	shift @found;
    } elsif ($export[0] lt $found[0]) {
	push @missing, shift @export;
    } else {
	# Ignore added symbols, for now.
	shift @found;
    }
}
if ($#export >= 0) { @missing = (@missing, @export); }
if ($#missing >= 0) {
    print STDERR "Missing symbols:\n\t", join("\n\t", @missing), "\n";
#    unlink $libfile;
    exit(1);
}
exit 0;
