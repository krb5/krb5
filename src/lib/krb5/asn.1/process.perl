#
# usage: perl process <input-c-file> <output-prefix> <c-flist> <o-flist>
#
$header = "";
$count = 0;
$pepyid = "";
$extrainclude = '#include <krb5/asn.1/KRB5-types-aux.h>' . "\n";

if ($#ARGV != 3) {die "Usage: process input-file.c output-prefix cflist-file oflist-file";}

print "processing ", $ARGV[0], "\n";
open(CFILE, "< $ARGV[0]") || die "can't open $ARGV[0]";
open(CFLIST, "> $ARGV[2]") || die "can't open $ARGV[2]";
open(OFLIST, "> $ARGV[3]") || die "can't open $ARGV[2]";

mainloop: while (<CFILE>) {
	next mainloop if /^# line/;
	if (/pepyid/) {
		$pepyid = $_;
	} elsif (/^\/\* ARGS|^free/) {
		print "processing output from $pepyid" if ($count == 0);
		close(OUTFILE);
		$ofile = "$ARGV[1]" . $count . ".c";
		open(OUTFILE, ">$ofile" ) || die "can't open file $ofile";
		print OUTFILE $pepyid if ($count == 0);
		print $ofile, "\n";
		@clist = (@clist, " " . $ofile);
		$count++;
		print OUTFILE $header;
		print OUTFILE $extrainclude;
		print OUTFILE $_;
	} elsif ($count == 0) {
		$header .= $_;
	} else {
		print OUTFILE $_;
	}
}
close(OUTFILE);
print CFLIST "TYPESSRCS= ", @clist, "\n";
close(CFLIST);
while ($cfile = shift(@clist))  {
	$cfile =~ s/.c$/.o/;
	@olist = (@olist, $cfile);
}
print OFLIST "TYPESOBJS=", @olist, "\n";
close(OFLIST);
#
#	$Source$
#	$Author$
#	$Id$
