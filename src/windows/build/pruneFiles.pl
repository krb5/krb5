#!perl -w

#use strict;
require "makeZip.pl";

sub pruneFiles {
    local ($xml, $config)   = @_;
    local $prunes   = $xml->{Prunes};
    if (! $prunes) {return 0;}
    
    # Use Unix find instead of Windows find.  Save PATH so we can restore it when we're done:
    local $savedPATH    = $ENV{PATH};
    $ENV{PATH}          = $config->{Config}->{unixfind}->{value}.";".$savedPATH;
    local $j=0;
    print "Info -- Processing prunes in ".`cd`."\n"     if ($verbose);
    while ($prunes->{Prune}->[$j]) {
        if (exists $prunes->{Prune}->[$j]->{name}) {    ## Don't process dummy entry!
            local $prune    = $prunes->{Prune}->[$j]->{name};
            local $flags    = $prunes->{Prune}->[$j]->{flags};
            $flags = "" if (!$flags);
            local $cmd    = "find . -".$flags."name $prune";
            print "Info -- Looking for filenames containing $prune\n";
            local $list = `$cmd`;
            foreach $target (split("\n", $list)) {
                print "Info -- Pruning $target\n" if ($verbose);
                ! system("rm -rf $target")              or die "Unable to prune $target";
                }
            }
        $j++;
        }
    $ENV{PATH} = $savedPATH;
    }

return 1;
