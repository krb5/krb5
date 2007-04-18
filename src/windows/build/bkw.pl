#!perl -w

#use strict;
use FindBin;
use File::Spec;
use File::Basename;
use lib "$FindBin::Bin/build/lib";
use Getopt::Long;
use Cwd;
use XML::Simple;
use Data::Dumper;
use Archive::Zip;
use Logger;
require "commandandcontrol.pl";
require "copyfiles.pl";
require "prunefiles.pl";
require "repository1.pl";
require "signfiles.pl";
require "zipXML.pl";

my $BAIL;
$0                      = fileparse($0);
my $MAKE                = 'NMAKE';
our $config;
local $bOutputCleaned   = 0;

sub get_info {
    my $cmd = shift || die;
    my $which = $^X.' which.pl';
    my $full = `$which $cmd`;
    return 0 if ($? / 256);
    chomp($full);
    $full = "\"".$full."\"";
    return { cmd => $cmd, full => $full};
    }

sub handler {
    my $sig = shift;
    my $bailmsg = "Bailing out due to SIG$sig!\n";
    my $warnmsg = <<EOH;
*********************************
* FUTURE BUILDS MAY FAIL UNLESS *
* BUILD DIRECTORIES ARE CLEANED *
*********************************
EOH
    $BAIL = $bailmsg.$warnmsg;
}

sub main {
    local $cmdline = "bkw.pl";
    foreach $arg (@ARGV) {$cmdline .= " $arg";}

    local @savedARGV    = @ARGV;

##++ Validate required conditions:

    # List of programs which must be in PATH:
    my @required_list = ('sed', 'awk', 'which', 'cat', 'rm', 'cvs', 'svn', 'doxygen', 
                         'hhc', 'candle', 'light', 'makensis', 'nmake', 'plink', 'filever');
    my $requirements_met    = 1;
    my $first_missing       = 0;
    my $error_list          = "";
    foreach my $required (@required_list) {
        if (!get_info($required)) {
            $requirements_met = 0;
            if (!$first_missing) {
                $first_missing = 1;
                $error_list = "Fatal -- Environment problem!  The following program(s) are not in PATH:\n";
                }
            $error_list .= "$required\n";
            }
        }
    if (!$requirements_met) {
        print $error_list;
        print "Info -- Update PATH or install the programs and try again.\n";
        exit(0);
        }

##-- Validate required conditions.
    
    use Time::gmtime;
    $ENV{DATE} = gmctime()." GMT";
    our $originalDir = `cd`;
    $originalDir =~ s/\n//g;

##++ Assemble configuration from config file and command line:

    local $config   = commandandcontrol("bkwconfig.xml", 0);

    # Set up convenience variables:
    local $odr      = $config->{Config};    ## Options, directories, repository, environment.
    our $verbose    = $odr->{verbose}->{def};
    our $vverbose   = $odr->{vverbose}->{def};
    local $src      = $odr->{src}->{value};
    local $wd       = $src."\\pismere";

##-- Assemble configuration from config file and command line.

    local $rverb    = $odr->{repository}->{value};

    if (! ($rverb =~ /skip/)) {
        local $len = 0;
        if (exists $odr->{username}->{value}) {
            $len = length $odr->{username}->{value};
            }
        if ($len < 1) {
            die "Fatal -- you won't get far accessing the repository without specifying a username.";
            }
        }

    if ( ($rverb =~ /checkout/) && (-d $wd) ){
        print "\n\nHEADS UP!!\n\n";
        print "/REPOSITORY CHECKOUT will cause everything under $wd to be deleted.\n";
        print "If this is not what you intended, here's your chance to bail out!\n\n\n";
        print "Are you sure you want to remove everything under $wd? ";
        my $char = getc;
        if (! ($char =~ /y/i))  {die "Info -- operation aborted by user."}
        !system("rm -rf $wd/*") or die "Fatal -- Couldn't clean $wd.";
        !system("rmdir $wd")    or die "Fatal -- Couldn't remove $wd.";
        }

##++ Begin repository action:
    repository1($config);

    @ARGV       = @savedARGV;
    # Now use the configuration file in the repository sources, forcing use of that config file:
    $config     = commandandcontrol("$src/pismere/athena/auth/krb5/src/windows/build/bkwconfig.xml", 1);
        
##-- End  repository action.

    # Set up convenience variables:
    $odr        = $config->{Config};    ## Options, directories, repository, environment.
    $verbose    = $odr->{verbose}->{def};
    $vverbose   = $odr->{vverbose}->{def};
    our $clean  = $odr->{clean}->{def};
    $src        = $odr->{src}->{value};
    $out        = $odr->{out}->{value};
    $wd         = "$src\\pismere";
    
# Begin logging:
    my $l;
    if ($odr->{logfile}->{def}) {
        print "Info -- logging to $odr->{logfile}->{value}.\n";
        $l = new Logger $odr->{logfile}->{value};
        $l->start;
        $l->no_die_handler;        ## Needed so XML::Simple won't throw exceptions.
        }

    print "Info -- Executing $cmdline\n";
    print "Info -- Option settings:\n";
    foreach $sw (sort keys %$odr) {
        local $val  = $odr->{$sw};
        if ($val->{def}) {
            if (exists $val->{value})   {print "        $sw $val->{value}\n";}
            else                        {print "        $sw\n";}
            }
        else                            {print "        no$sw\n";}
        }

    if ($vverbose) {print "Debug -- Config: ".Dumper($config);}
    
    if ( ($rverb =~ /checkout/) && $clean) {
        print "Warning -- Because sources afe being checked out, make clean will not be run.\n";
        $clean  = $odr->{clean}->{def}    = 0;
        }

    if ($clean && $odr->{package}->{def}) {
        print "Info -- /clean forces /nopackage.\n";
        $odr->{package}->{def} = 0;
        }

    # Test the unix find command:
    if (! exists $odr->{unixfind}->{value})    {
        $odr->{unixfind}->{value}   = "C:\\tools\\cygwin\\bin";
         }
    local $unixfind     = $odr->{unixfind}->{value};

    local $savedPATH    = $ENV{PATH};
    $ENV{PATH}          = $unixfind.";".$savedPATH;
    print "Info -- chdir to ".`cd`."\n"         if ($verbose);
    if (-e "a.tmp") {!system("rm a.tmp")        or die "Fatal -- Couldn't clean temporary file a.tmp.";}
    !system("find . -name a.tmp > b.tmp 2>&1")  or die "Fatal -- find test failed.";
    local $filesize = -s "b.tmp";
    $ENV{PATH} = $savedPATH;
    if ($filesize > 0) {
        die "Fatal -- $unixfind does not appear to be a path to a UNIX find command.";
        }
        
    ##++ Read in the version information to be able to update the 
    #  site-local files in the install build areas.
    # ** Do this now (after repository update and before first zip) 
    #    because making zip files requires some configuration data be set up.
    local $version_path = $config->{Stages}->{Package}->{Config}->{Paths}->{Versions}->{path};
    open(DAT, "$src/$version_path")     or die "Could not open $version_path.";
    @raw = <DAT>;
    close DAT;
    foreach $line (@raw) {
        chomp $line;
        if ($line =~ /#define/) {                   # Process #define lines:
            $line =~ s/#define//;                   # Remove #define token
            $line =~ s/^\s+//;                      #  and leading & trailing whitespace
            $line =~ s/\s+$//;
            local @qr = split("\"", $line);         # Try splitting with quotes
            if (exists $qr[1]) {
                $qr[0] =~ s/^\s+//;                 #  Clean up whitespace
                $qr[0] =~ s/\s+$//;
                $config->{Versions}->{$qr[0]} = $qr[1]; # Save string
                }
            else {                                  # No quotes, so
                local @ar = split(" ", $line);      #  split with space
                $ar[0] =~ s/^\s+//;                 #  Clean up whitespace
                $ar[0] =~ s/\s+$//;
                $config->{Versions}->{$ar[0]} = $ar[1]; # and  save numeric value
                }
            }
        }
    
    # Check that the versions we will need for site-local have been defined:
    my @required_versions = ('VER_PROD_MAJOR', 'VER_PROD_MINOR', 'VER_PROD_REV', 
                             'VER_PROD_MAJOR_STR', 'VER_PROD_MINOR_STR', 'VER_PROD_REV_STR', 
                             'VER_PRODUCTNAME_STR');
    $requirements_met   = 1;
    $first_missing      = 0;
    $error_list         = "";
    foreach my $required (@required_versions) {
        if (! exists $config->{Versions}->{$required}) {
            $requirements_met = 0;
            if (!$first_missing) {
                $first_missing = 1;
                $error_list = "Fatal -- The following version(s) are not defined in $src/$version_path.\n";
                }
            $error_list .= "$required\n";
            }
        }
    if (!$requirements_met) {
        print $error_list;
        exit(0);
        }
    
    # Apply any of these tags to filestem:
    my $filestem    = $config->{Stages}->{PostPackage}->{Config}->{FileStem}->{name};
    $filestem       =~ s/%VERSION_MAJOR%/$config->{Versions}->{'VER_PROD_MAJOR_STR'}/;
    $filestem       =~ s/%VERSION_MINOR%/$config->{Versions}->{'VER_PROD_MINOR_STR'}/;
    $filestem       =~ s/%VERSION_PATCH%/$config->{Versions}->{'VER_PROD_REV_STR'}/;
    $config->{Stages}->{PostPackage}->{Config}->{FileStem}->{name}    = $filestem;
    ##-- Read in the version information & set config info.

##++ Repository action, part 2:
    if ($rverb =~ /checkout/) {        
       if (! $bOutputCleaned) {                    ## In case somebody cleaned $out before us.
           if (-d $out)    {!system("rm -rf $out/*")   or die "Fatal -- Couldn't clean $out."}    ## Clean output directory.
           else            {mkdir($out);}
           $bOutputCleaned = 1;
           }
       zipXML($config->{Stages}->{FetchSources}, $config); ## Make zips.
       }
##-- End  repository action, part 2.

##++ Make action:
    if (    ($odr->{make}->{def}) ) {
        if ($verbose) {print "Info -- *** Begin preparing for build.\n";}

        chdir("$wd") or die "Fatal -- couldn't chdir to $wd\n";
        print "Info -- chdir to ".`cd`."\n"             if ($verbose);
    
        my ($path, $destpath);
        
        # Copy athena\scripts\site\graft\krb5\Makefile.src to athena\auth\krb5:
        $path = "scripts\\site\\graft\\krb5\\Makefile.src";
        if (!-e  $path) {die "Fatal -- Expected file $wd\\$path not found.";}
        $destpath = "athena\\auth\\krb5\\Makefile.src";
        !system("echo F | xcopy /D $wd\\$path $wd\\$destpath /Y > NUL") or die "Fatal -- Copy of $wd\\$path to $wd\\$destpath failed.";
        print "Info -- copied $wd\\$path to $wd\\$destpath\n"   if ($verbose);;
        
        # Add DEBUG_SYMBOL to .../wshelper/Makefile.src:
        $path = "athena\\wshelper\\wshelper\\Makefile.src";
        if (!-e  $path) {die "Fatal -- Expected file $wd\\$path not found.";}
        if (system("grep DEBUG_SYMBOL $path > NUL") != 0) {
            !system ("echo DEBUG_SYMBOL=1 >> $wd\\$path") or die "Fatal -- Append line to file failed.\n";
            print "Info -- Added DEBUG_SYMBOL to $wd\\$path\n"  if ($verbose);
            }
        
        # Prune any unwanted directories before the build:
        pruneFiles($config->{Stages}->{Make}, $config);

        if ($verbose) {print "Info -- ***   End preparing for build.\n";}
    
        my ($buildtarget, $buildtext);
        if ($clean) {
            $buildtarget = "clean" ;
            $buildtext   = " clean."
            }
        else {
            $buildtarget = "" ;
            $buildtext   = "."
            }
        
        chdir("$wd\\athena") or die "Fatal -- couldn't chdir to source directory $wd\\athena\n";
        print "Info -- chdir to ".`cd`."\n"         if ($verbose);
        local $dbgswitch = ($odr->{debug}->{def}) ? " " : "NODEBUG=1";
        !system("perl ../scripts/build.pl --softdirs --nolog $buildtarget $dbgswitch BUILD_KFW=1 BUILD_OFFICIAL=1 DEBUG_SYMBOL=1")
            or die "Fatal -- build $buildtarget failed.";
            
        chdir("$wd")                        or die "Fatal -- couldn't chdir to $wd.";
        print "Info -- chdir to ".`cd`."\n" if ($verbose);
        if ($clean) {
            if (-d "staging") {
                !system("rm -rf staging")   or die "Fatal -- Couldn't remove $wd\\staging.";
                }
            }
    
        if ($verbose) {print "Info -- ***   End build".$buildtext."\n";}
        }                                           ## End make conditional.
    else {print "Info -- *** Skipping build.\n"    if ($verbose);}
##-- Make action.
        
##++ Package action:
    if (! $odr->{package}->{def}) {      ## If /clean, nopackage will be set.
        print "Info -- *** Skipping packaging.\n";
        if ((-d $out) && ! $bOutputCleaned) {
            print "Warning -- *** Output directory $out will not be cleaned.\n";
            }
        }
    else {
        if ($verbose) {print "Info -- *** Begin prepackage.\n";}

        if (! $bOutputCleaned) {                        ## In case somebody cleaned $out before us.
            if (-d $out)    {!system("rm -rf $out/*")   or die "Fatal -- Couldn't clean $out."}    ## Clean output directory.
            else            {mkdir($out);}
            $bOutputCleaned = 1;
            }

        # The build results are copied to a staging area, where the packager expects to find them.
        #  We put the staging area in the fixed area .../pismere/staging.
        my $prepackage  = $config->{Stages}->{PrePackage};
        my $staging     = "$wd\\staging";
        chdir($wd)                          or die "Fatal -- couldn't chdir to $wd\n";
        print "Info -- chdir to ".`cd`."\n" if ($verbose);
        if (-d "staging") {
            !system("rm -rf $staging/*")        or die "Fatal -- Couldn't clean $staging.";
            }
        else {
            mkdir($staging)                     or die "Fatal -- Couldn't create $staging.";
            }
        
        # Force Where From and To are relative to:
        $prepackage->{CopyList}->{Config}->{From}->{root}   = "$wd\\athena";
        $prepackage->{CopyList}->{Config}->{To}->{root}     = "$wd\\staging";
        copyFiles($prepackage->{CopyList}, $config);        ## Copy any files [this step takes a while]

        # Sign files:
        chdir($staging) or die "Fatal -- couldn't chdir to $staging\n";
        print "Info -- chdir to ".`cd`."\n"     if ($verbose);
        if ($odr->{sign}->{def}) {
            signFiles($config->{Stages}->{PostPackage}->{Config}->{Signing}, $config);
            }
            
        # Create working directories for building the installers:
        if (-d "$wd\\buildwix")    {!system("rm -rf $wd\\buildwix/*")               or die "Fatal -- Couldn't clean $wd\\buildwix."}    
        !system("echo D | xcopy /s $wd\\staging\\install\\wix\\*.* $wd\\buildwix")  or die "Fatal -- Couldn't create $wd\\buildwix.";
        if (-d "$wd\\buildnsi")    {!system("rm -rf $wd\\buildnsi/*")               or die "Fatal -- Couldn't clean $wd\\buildnsi."}    
        !system("echo D | xcopy /s $wd\\staging\\install\\nsis\\*.* $wd\\buildnsi") or die "Fatal -- Couldn't create $wd\\buildnsi.";

        chdir("$staging\\install\\wix") or die "Fatal -- Couldn't cd to $staging\\install\\wix";
        print "Info -- chdir to ".`cd`."\n"     if ($verbose);
        # Correct errors in files.wxi:
        !system("sed 's/WorkingDirectory=\"\\[dirbin\\]\"/WorkingDirectory=\"dirbin\"/g' files.wxi > a.tmp") or die "Fatal -- Couldn't modify files.wxi.";
        !system("mv a.tmp files.wxi") or die "Fatal -- Couldn't update files.wxi.";
            
        # Make sed script to run on the site-local configuration files:
        local $tmpfile      = "site-local.sed" ;
        if (-e $tmpfile) {system("del $tmpfile");}
        # Basic substitutions:
        local $dblback_wd   = $wd;
        $dblback_wd         =~ s/\\/\\\\/g;
        !system("echo s/%BUILDDIR%/$dblback_wd/ >> $tmpfile")               or die "Fatal -- Couldn't modify $tmpfile.";    
        local $dblback_staging  = "$wd\\staging";
        $dblback_staging        =~ s/\\/\\\\/g;
        !system("echo s/%TARGETDIR%/$dblback_staging/ >> $tmpfile")         or die "Fatal -- Couldn't modify $tmpfile.";    
        local $dblback_sample   = "$wd\\staging\\sample";
        $dblback_sample         =~ s/\\/\\\\/g;
        !system("echo s/%CONFIGDIR-WIX%/$dblback_sample/ >> $tmpfile")      or die "Fatal -- Couldn't modify $tmpfile.";    
        !system("echo s/%CONFIGDIR-NSI%/$dblback_staging/ >> $tmpfile")     or die "Fatal -- Couldn't modify $tmpfile.";    
        !system("echo s/%VERSION_MAJOR%/$config->{Versions}->{'VER_PROD_MAJOR_STR'}/ >> $tmpfile")  or die "Fatal -- Couldn't modify $tmpfile.";    
        !system("echo s/%VERSION_MINOR%/$config->{Versions}->{'VER_PROD_MINOR_STR'}/ >> $tmpfile")  or die "Fatal -- Couldn't modify $tmpfile.";    
        !system("echo s/%VERSION_PATCH%/$config->{Versions}->{'VER_PROD_REV_STR'}/ >> $tmpfile")    or die "Fatal -- Couldn't modify $tmpfile.";    
        # Strip out some defines so they can be replaced:  [used for site-local.nsi]
        !system("echo /\^!define\.\*RELEASE\.\*\$/d >> $tmpfile")           or die "Fatal -- Couldn't modify $tmpfile.";    
        !system("echo /\^!define\.\*DEBUG\.\*\$/d >> $tmpfile")             or die "Fatal -- Couldn't modify $tmpfile.";    
        !system("echo /\^!define\.\*BETA\.\*\$/d >> $tmpfile")              or die "Fatal -- Couldn't modify $tmpfile.";    

        # Run the script on site-local.wxi:
        !system("sed -f $tmpfile site-local-tagged.wxi > $wd\\buildwix\\site-local.wxi")   or die "Fatal -- Couldn't modify site-local.wxi.";

        # Now update site-local.nsi:
        chdir "..\\nsis";
        print "Info -- chdir to ".`cd`."\n"                                 if ($verbose);
        !system("sed -f ..\\wix\\$tmpfile site-local-tagged.nsi > b.tmp")   or die "Fatal -- Couldn't modify site-local.wxi.";
        # Add DEBUG or RELEASE:
        if ($odr->{debug}->{def}) {                    ## debug build
            !system("echo !define DEBUG >> b.tmp")     or die "Fatal -- Couldn't modify b.tmp.";    
            }
        else {                                         ## release build
            !system("echo !define RELEASE >> b.tmp")   or die "Fatal -- Couldn't modify b.tmp.";
            }
        # Add BETA if present:
        if (exists $config->{Versions}->{'BETA_STR'}) {
            !system("echo !define BETA $config->{Versions}->{'BETA_STR'} >> b.tmp") or die "Fatal -- Couldn't modify b.tmp.";    
            }
        !system("mv -f b.tmp $wd\\buildnsi\\site-local.nsi")                        or die "Fatal -- Couldn't replace site-local.nsi.";

        # Run the script on nsi-includes-tagged.nsi:
        !system("sed -f ..\\wix\\$tmpfile nsi-includes-tagged.nsi > $wd\\buildnsi\\nsi-includes.nsi")  or die "Fatal -- Couldn't modify nsi-includes.nsi.";
        !system("rm ..\\wix\\$tmpfile")                                     or die "Fatal -- Couldn't remove $tmpfile.";

        if ($verbose) {print "Info -- ***   End prepackage.\n";}
        
        if ($verbose) {print "Info -- *** Begin package.\n";}
        # Make the msi:
        chdir("$wd\\buildwix")                      or die "Fatal -- Couldn't cd to $wd\\buildwix";
        print "Info -- *** Make .msi:\n"            if ($verbose);
        print "Info -- chdir to ".`cd`."\n"         if ($verbose);
        !system("$MAKE")                            or die "Error -- msi installer build failed.";
                
        chdir("$wd\\buildnsi")                      or die "Fatal -- Couldn't cd to $wd\\buildnsi";
        print "Info -- *** Make NSIS:\n"            if ($verbose);
        print "Info -- chdir to ".`cd`."\n"         if ($verbose);
        !system("cl.exe killer.cpp advapi32.lib")   or die "Error -- nsis killer.exe not built.";
        !system("rename killer.exe Killer.exe")     or die "Error -- Couldn't rename killer.exe";
        !system("makensis kfw.nsi")                 or die "Error -- executable installer build failed.";

# Begin packaging extra items:
        chdir($wd)                                  or die "Fatal -- Couldn't cd to $wd";
        print "Info -- chdir to ".`cd`."\n"         if ($verbose);

        zipXML($config->{Stages}->{PostPackage}, $config);                      ## Make zips.

        $config->{Stages}->{PostPackage}->{CopyList}->{Config} = $config->{Stages}->{PostPackage}->{Config};    ## Use the post package config.
        $config->{Stages}->{PostPackage}->{CopyList}->{Config}->{From}->{root}  = "$src\\pismere";
        $config->{Stages}->{PostPackage}->{CopyList}->{Config}->{To}->{root}    = $out;
        copyFiles($config->{Stages}->{PostPackage}->{CopyList}, $config);       ## Copy any files

        !system("rm -rf $wd\\buildwix")             or die "Fatal -- Couldn't remove $wd\\buildwix.";
        !system("rm -rf $wd\\buildnsi")             or die "Fatal -- Couldn't remove $wd\\buildnsi.";

        chdir($out)                                 or die "Fatal -- Couldn't cd to $out";
        print "Info -- chdir to ".`cd`."\n"         if ($verbose);
        if ($odr->{sign}->{def}) {
            signFiles($config->{Stages}->{PostPackage}->{Config}->{Signing}, $config);
            }

        if ($verbose) {print "Info -- ***   End package.\n";}
        }
##-- Package action.

    system("rm -rf $src/a.tmp");                ## Clean up junk.
    system("rm -rf $out/a.tmp");                ## Clean up junk.
    system("rm -rf $out/ziptemp");              ## Clean up junk.

# End logging:
    if ($odr->{logfile}->{def})   {$l->stop;}

    return 0;
    }                                           ## End subroutine main.

$SIG{'INT'} = \&handler;
$SIG{'QUIT'} = \&handler;

exit(main());