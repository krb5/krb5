#

die "Please specify input and output filenames" if($#ARGV != 1);

open INF, '<', $ARGV[0] or die "Can't open input file";
open OUF, '>', $ARGV[1] or die "Can't open output file";

print OUF <<EOS;
#include<khimaira.h>

    khui_action khui_actions[] = {
EOS

# skip first line
    <INF>;

while(<INF>) {
    print OUF "{".$_."},\n";
}

print OUF <<EOS;
};

int khui_n_actions = sizeof(khui_actions) / sizeof(khui_action);

EOS

close INF;
close OUF;
