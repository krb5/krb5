#!/usr/athena/bin/perl
eval 'exec /usr/athena/bin/perl -S $0 ${1+"$@"}'
	if $running_under_some_shell;

@convC = ();
@convK = ();
@convD = ();

open H, "<$ARGV[0]" || die "aaaa! $!";
open D, "<$ARGV[1]";

LINE:
while (! eof H) {
    $_ = <H>;
    chop;
    # get calling convention info for function decls
    # what about function pointer typedefs?
    # need to verify unhandled syntax actually triggers a report, not ignored
    # blank lines
    if (/^[ \t]*$/) {
        next LINE;
    }
  Top:
    # drop preprocessor directives
    if (/^ *#/) {
        next LINE;
    }
    if (/^ *\?==/) {
        next LINE;
    }
    s/#.*$//;
    if (/^} *$/) {
        next LINE;
    }
    # strip comments
  Cloop1:
    if (/\/\*./) {
	s;/\*[^*]*;/*;;
	s;/\*\*([^/]);/*$1;;
	s;/\*\*$;/*;;
	s;/\*\*/; ;g;
	goto Cloop1;
    }
    # multi-line comments?
    if (/\/\*$/) {
	$_ .= "\n";
	$len1 = length;
	$_ .= <H>;
	chop if $len1 < length;
	goto Cloop1 if /\/\*./;
    }
    # blank lines
    if (/^[ \t]*$/) {
        next LINE;
    }
    if (/ *extern "C" {/) {
        next LINE;
    }
    # elide struct definitions
  Struct1:
    if (/{[^}]*}/) {
	s/{[^}]*}/ /g;
	goto Struct1;
    }
    # multi-line defs
    if (/{/) {
	$_ .= "\n";
	$len1 = length;
	$_ .= <H>;
	chop if $len1 < length;
	goto Struct1;
    }
  Semi:
    unless (/;/) {
	$_ .= "\n";
	$len1 = length;
	$_ .= <H>;
	chop if $len1 < length;
	s/\n/ /g;
	s/[ \t]+/ /g;
	s/^[ \t]*//;
	goto Top;
    }
    if (/^typedef[^;]*;/) {
	s/^typedef[^;]*;//g;
	goto Semi;
    }
    if (/^struct[^\(\)]*;/) {
	s/^struct[^\(\)]*;//g;
	goto Semi;
    }
    # should just have simple decls now; split lines at semicolons
    s/ *;[ \t]*$//;
    s/ *;/\n/g;
    if (/^[ \t]*$/) {
        next LINE;
    }
    s/[ \t]*$//;
    goto Notfunct unless /\(.*\)/;
    # here, is probably function decl
    # strip simple arg list - parens, no parens inside; discard, iterate.
    # the iteration should deal with function pointer args.
  Striparg:
    if (/ *\([^\(\)]*\)/) {
	s/ *\([^\(\)]*\)//g;
	goto Striparg;
    }
    # replace return type etc with one token indicating calling convention
    if (/CALLCONV/) {
	if (/KRB5_CALLCONV_C/) {
	    s/^.*KRB5_CALLCONV_C *//;
	    push @convC, $_;
	} elsif (/KRB5_CALLCONV/) {
	    s/^.*KRB5_CALLCONV *//;
	    push @convK, $_;
	} else {
	    die horribly;
	}
	goto Hadcallc;
    }
    # deal with no CALLCONV indicator
    s/^.* (\w+) *$/$1/;
    push @convD, $_;
  Hadcallc:
    goto Skipnotf;
  Notfunct:
    # probably a variable
    s/^/VARIABLE_DECL /;
  Skipnotf:
    # toss blank lines
    if (/^[ \t]*$/) {
        next LINE;
    }
}

print join("\n\t", "Using default calling convention:", sort(@convD));
print join("\n\t", "\nUsing KRB5_CALLCONV:", sort(@convK));
print join("\n\t", "\nUsing KRB5_C_CALLCONV:", sort(@convC));
print "\n";

%conv = ();
map { $conv{$_} = "default"; } @convD;
map { $conv{$_} = "KRB5"; } @convK;
map { $conv{$_} = "KRB5_C"; } @convC;

LINE2:
while (! eof D) {
    $_ = <D>;
    chop;
    #
    if (/^;/) {
        $printit = 0;
        next LINE2;
    }
    if (/^[ \t]*$/) {
        $printit = 0;
        next LINE2;
    }
    if (/^EXPORTS/) {
        $printit = 0;
        next LINE2;
    }
    s/[ \t]*//g;
    my($xconv);
    if (/!CALLCONV/) {
	$xconv = "KRB5_C";
    } else {
	$xconv = "KRB5";
    }
    s/;.*$//;
    if (!defined($conv{$_})) {
	print "No calling convention specified for $_!\n";
    } elsif ($conv{$_} != $xconv) {
	print "Function $_ should have calling convention '$xconv', but has '$conv{$_}' instead.\n";
    } else {
#	print "Function $_ is okay.\n";
    }
}

#print "Calling conventions defined for: ", keys(%conv);
