#!perl -w

#use strict;
use Data::Dumper;

require "signfiles.pl";

sub makeZip {
    local ($zip, $config)   = @_;

    local $src          = $config->{CommandLine}->{Directories}->{src}->{path};
    local $out          = $config->{CommandLine}->{Directories}->{out}->{path};
    local @switches     = $config->{CommandLine}->{Options};
    local $zipname      = $zip->{filename};
    local $filestem     = $config->{Stages}->{PostPackage}->{Config}->{FileStem}->{name};
    $zipname            =~ s/%filestem%/$filestem/g;
    if (exists $zip->{Requires}) {
        local $bMakeIt  = 1;
        local $rverb    = $switches[0]->{repository}->{value};
        local $j        = 0;
        while ($zip->{Requires}->{Switch}[$j]) {                    ## Check Require switches
            local $switch    = $zip->{Requires}->{Switch}[$j];
            if (exists $switch->{name}) {                           ## Ignore dummy entry
                # We handle REPOSITORY and CLEAN switches:
                if ($switch->{name} =~ /REPOSITORY/i) {
                    $bMakeIt &&= ($switch->{value} =~ /$rverb/i);   ## Repository verb must match requirement
                    }
                 elsif ($switch->{name} =~ /CLEAN/i) {               ## Clean must be specified
                    $bMakeIt &&= $clean;
                    }
                 else {print "Error -- Unsupported switch $switch->{name} in Requires in ".Dumper($zip);
                    $bMakeIt    = 0;
                    }
                 }
             $j++;
             }   
        if ( !$bMakeIt ) {
            if (exists $zip->{Requires}->{ErrorMsg}) {
                print "Error -- $zip->{Requires}->{ErrorMsg}->{text}\n";
                }
            else {
                print "Error -- requirements not met for building $zipname.\n";
                }
            return 0;
            }
        }
        
    local $ziptemp    = "$out\\ziptemp";
    chdir "$out";
    print "Info -- chdir to ".`cd`."\n"         if ($verbose);
    system("rm -rf $ziptemp")                 if (-d $ziptemp);
    die "Fatal -- Couldn't remove $ziptemp"   if (-d $ziptemp);
    mkdir($ziptemp);
    # Set up the zip's config section:
    $zip->{Config}                                  = $config->{Stages}->{PostPackage}->{Config};
    # Add to the copylist's config section.  Don't copy Postpackage->Config, 
    #  because the CopyList's Config might contain substitution tags.
    $zip->{CopyList}->{Config}->{FileStem}->{name}  = $config->{Stages}->{PostPackage}->{Config}->{FileStem}->{name};
    $zip->{CopyList}->{Config}->{From}->{root}      = "$src\\pismere";  ## Add zip-specific config settings.
    $zip->{CopyList}->{Config}->{To}->{root}        = "$ziptemp\\$zip->{topdir}";
    copyFiles($zip->{CopyList}, $config);
    # Drop down into <out>/ziptemp so the path to the added file won't include <out>:
    chdir $ziptemp;
    print "Info -- chdir to ".`cd`."\n"         if ($verbose);

    # Prune any unwanted files or directories from the directory we're about to zip:
    if (exists $zip->{Prunes}) {
        # Use Unix find instead of Windows find.  Save PATH so we can restore it when we're done:
        local $savedPATH    = $ENV{PATH};
        $ENV{PATH}          = $config->{CommandLine}->{Directories}->{unixfind}->{path}.";".$savedPATH;
        local $prunes       = $zip->{Prunes};
        local $j            = 0;
        print "Info -- Processing prunes in ".`cd`."\n" if ($verbose);
        while ($prunes->{Prune}->[$j]) {
            if (exists $prunes->{Prune}->[$j]->{name}) {        ## Don't process dummy entry!
                local $prune    = $prunes->{Prune}->[$j]->{name};
                local $flags    = $prunes->{Prune}->[$j]->{flags};
                $flags = "" if (!$flags);
                local $cmd    = "find . -".$flags."name $prune";
                print "Info -- Looking for filenames containing $prune\n";
                local $list = `$cmd`;
                foreach $target (split("\n", $list)) {
                    print "Info -- Pruning $target\n" if ($verbose);
                    !system("rm -rf $target")   or die "Error -- Couldn't remove $target.";;
                    }
                }
            $j++;
            }
        $ENV{PATH} = $savedPATH;
        }
                    
    # Sign files:
    if ($switches[0]->{sign}->{value}) {
        signFiles($zip->{Config}->{Signing}, $config);
        }
            
    local $zipfile  = Archive::Zip->new();
    local $topdir   = $zip->{topdir};
    $topdir         =~ s/%filestem%/$filestem/g;
    $zipfile->addTree('.', $topdir);
    if (-e $zipname)    {!system("rm -f $zipname")     or die "Error -- Couldn't remove $zipname.";}
    $zipfile->writeToFileNamed($zipname);
    print "Info -- created $out\\$zipname.\n"  if ($verbose);
       # move .zip from <out>/ziptemp to <out>.
    !system("mv -f $zipname     ..")                    or die "Error -- Couldn't move $zipname to ..";
    }
    
return 1;