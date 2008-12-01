#!/usr/bin/perl

#
# Copyright (c) 2004 Massachusetts Institute of Technology
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation
# files (the "Software"), to deal in the Software without
# restriction, including without limitation the rights to use, copy,
# modify, merge, publish, distribute, sublicense, and/or sell copies
# of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#


# This is a simple script that is used for generating C code from CSV
#files.  We expect three arguments, the <input> which is the .csv file
#to be parsed, a <config> which is a configuration file and the
#<output>.  

#   The configuration file is a perl file which defines the following
#variables :

# $skip_lines : the number of lines to skip in the csv.  The default is 0

# @pquote : an array of boolean integers that specify whether or not
# to quote the specific field using double quotes.  The default is to
# not quote anything.

# $file_prefix : the prefix for the file

# $record_prefix : the prefix for each record

# $field_sep : the field separator.  The default is ','

# $record_postfix : the postfix for each record

# $record_sep : A record separator.  Only shows up between records.

# $file_postfix : the postfix for the entire file

use Text::ParseWords;

sub do_nothingus {
}

if($#ARGV != 2) {
    print "Usage: ccsv.pl <input-filename> <config-filename> <output-filename>\n";
    die;
}

$infn=$ARGV[0];
$cfgfn=$ARGV[1];
$outfn=$ARGV[2];

$skip_lines = 0;
@pquote = {};
$file_prefix = "";
$record_prefix = "";
$finc = "";
$field_sep = ",";
$record_postfix = "";
$record_sep = "\n";
$file_postfix = "";
$record_parser = \&do_nothingus;

($inbase) = ($infn =~ m/^(\w*)/);

do $cfgfn;

open(IN, "<".$infn) or die "Can't open input file:".$infn;
open(OUT, ">".$outfn) or die "Can't open output file:".$outfn;

$first_line = 1;

while(<IN>) {
    chomp $_;
    if (m/^\#/) {
        if (m/^\#\@/) {
            ($inc) = m/^\#\@(.*)/;
            $finc = $finc.$inc."\n";
        } else {
            # ignore
        }
    } elsif ($skip_lines > 0) {
        $skip_lines--;
    } else {
	if($first_line == 0){
	    print OUT $record_sep;
	} else {
            $file_prefix =~ s/\$finc/$finc/;
            print OUT $file_prefix;
	    $first_line = 0;
	}

	@fields = &parse_line(',',0,$_);
	for(@fields) {
	    chomp;
	    s/^\s*//;
	}

	&$record_parser(\@fields);

	print OUT $record_prefix;
	for(my $i=0; $i <= $#fields; $i++) {
	    print OUT $field_sep if $i != 0;
	    print OUT 'L"' if $pquote[$i] == 1;
	    print OUT $fields[$i];
	    print OUT '"' if $pquote[$i] == 1;
	}
	print OUT $record_postfix;
    }
}

if ($first_line == 1) {
    print OUT $file_prefix;
}

print OUT $file_postfix;

close INF;
close OUT;
