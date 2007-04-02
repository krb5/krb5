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
require "copyfiles.pl";
require "signfiles.pl";
require "makeZip.pl";

my $BAIL;
$0 = fileparse($0);
my $OPT = {foo => 'bar'};
my $MAKE = 'NMAKE';
our $config;

sub get_info {
    my $cmd = shift || die;
    my $which = $^X.' which.pl';
    my $full = `$which $cmd`;
    return 0 if ($? / 256);
    chomp($full);
    $full = "\"".$full."\"";
    return { cmd => $cmd, full => $full};
    }

sub usage {
    print <<USAGE;
Usage: $0 (-f --config) config-file [options] NMAKE-options

  Options are case insensitive.

  Options:
    /help /?           usage information (what you now see).
    /config /c path    Path to config file.
    /srcdir /r dir     Source directory to use.  Should contain 
                       pismere/athena.  If cvstag or svntag is null, 
                       the directory should be prepopulated.
    /outdir /o dir     Directory to be created where build results will go
    /repository checkout | co \\  What repository action to take.
                update   | up  ) Options are to checkout, update or 
                skip          /  take no action [skip].
    /username /u name  username used to access svn if checking out.
    /cvstag /c tag   \\ If non-empty, the tag is appended to cvs and svn
    /svntag /s tag   / commands to select the rev to fetch.
    /debug /d          Do debug make instead of release make.
    /nomake            Skip make step.
    /clean             Build clean target.
    /nopackage         Skip packaging step.
    /sign              Sign files
    /nosign            Don't sign files
    /verbose /v        Debug mode - verbose output.
    /logfile /l path   Where to write output.  Default is bkw.pl.log
    /nolog             Don't save output
  Other:
    NMAKE-options      any options you want to pass to NMAKE, which can be:
                       (note: /nologo is always used)

USAGE
    system("$MAKE /?");
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
    Getopt::Long::Configure('no_bundling', 'no_auto_abbrev',
           'no_getopt_compat', 'require_order',
           'ignore_case', 'pass_through',
           'prefix_pattern=(--|-|\+|\/)',
           );
    GetOptions($OPT,
           'help|h|?',
           'cvstag|c:s',
           'svntag|s:s',
           'srcdir|r:s',
           'outdir|o:s',
           'debug|d',
           'config|f:s',
           'logfile|l:s',
           'nolog',
           'repository:s',
           'username|u:s',
           'verbose|v',
           'vverbose',
           'nomake',
           'clean',
           'nopackage',
           'sign',
           'nosign',
           );

    if ( $OPT->{help} ) {
        usage();
        exit(0);
        }
        
##++ Validate required conditions:

    if ($OPT->{config}) {}
    else {
        print "Fatal -- Configuration file must be specified.\n";
        usage();
        exit(0);
        }

    # List of programs which must be in PATH:
    my @required_list = ('sed', 'awk', 'which', 'cat', 'rm', 'cvs', 'svn', 'doxygen', 'hhc', 'candle', 'light', 'makensis', 'nmake', 'plink');
    my $requirements_met = 1;
    my $first_missing = 0;
    my $error_list = "";
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

    my $configfile;
    $configfile = $OPT->{config};

    print "Info -- Reading configuration from $configfile.\n";

    # Get configuration file:
    my $xml = new XML::Simple();
    $config = $xml->XMLin($configfile);

    # Set up convenience variables:
    my (@switches, @paths, @tags, @fetch);
    @switches   = $config->{CommandLine}->{Options};
    @paths      = $config->{CommandLine}->{Directories};
    @tags       = $config->{CommandLine}->{Tags};
    @fetch      = $config->{Stages}->{FetchSources}->{Config};

    # Update the configuration with overrides from the command line:
    $tags[0]->{cvs}->{value} = $OPT->{cvstag}                   if exists $OPT->{cvstag};
    $tags[0]->{svn}->{value} = $OPT->{svnurl}                   if exists $OPT->{svnurl};
    $paths[0]->{src}->{path} = $OPT->{srcdir}                   if exists $OPT->{srcdir};
    $paths[0]->{out}->{path} = $OPT->{outdir}                   if exists $OPT->{outdir};
    $switches[0]->{debug}->{value} = $OPT->{debug}              if exists $OPT->{debug};
    $switches[0]->{clean}->{value} = 1                          if exists $OPT->{clean};
    $switches[0]->{repository}->{value} = $OPT->{repository}    if exists $OPT->{repository};
    $fetch[0]->{USERNAME}->{name} = $OPT->{username}            if exists $OPT->{username};
    $switches[0]->{nomake}->{value} = 1                         if exists $OPT->{nomake};
    $switches[0]->{nopackage}->{value} = 1                      if exists $OPT->{nopackage};
    $switches[0]->{verbose}->{value} = $OPT->{verbose}          if exists $OPT->{verbose};
    $switches[0]->{vverbose}->{value} = $OPT->{verbose}         if exists $OPT->{vverbose};
    if (exists $OPT->{logfile}) {
        $switches[0]->{logfile}->{path} = $OPT->{logfile};
        $switches[0]->{logfile}->{value} = 1;
        }
    if (exists $OPT->{nolog}) {
        $switches[0]->{logfile}->{value} = 0;
        }
    if (exists $OPT->{sign}) {
        $switches[0]->{sign}->{timestampserver} = $OPT->{sign};
        $switches[0]->{sign}->{value} = 1;
        }
    if (exists $OPT->{nosign}) {
        $switches[0]->{sign}->{value} = 0;
        }
    our $verbose    = $config->{CommandLine}->{Options}->{verbose}->{value};
    our $vverbose   = $config->{CommandLine}->{Options}->{vverbose}->{value};
    our $clean      = $switches[0]->{clean}->{value};
    local $src      = $paths[0]->{src}->{path};
    local $out      = $paths[0]->{out}->{path};

    if ($clean && !$switches[0]->{nopackage}->{value}) {
        print "Info -- /clean forces /nopackage.\n";
        $switches[0]->{nopackage}->{value} = 1;
        }

    if ($vverbose) {print "Debug -- Config: ".Dumper($config);}
    
    # Examples of use:
    #print "Logfile path: $switches[0]->{log}->{path}\n";
    #print "src path: $paths[0]->{src}->{path}\n";
    #print "cvs tag: $tags[0]->{cvs}->{value}\n";
    #print "CVSROOT:   $fetch[0]->{CVSROOT}->{name}\n";

##-- Assemble configuration from config file and command line.

    my $sw = $switches[0]->{repository}->{value};
    my $rverb;
    if       ($sw =~ /skip/i)       {$rverb = "skip";}
    elsif    ($sw =~ /update/i)     {$rverb = "update";}
    elsif    ($sw =~ /up/i)         {$rverb = "update";}
    elsif    ($sw =~ /checkout/i)   {$rverb = "checkout";}
    elsif    ($sw =~ /co/i)         {$rverb = "checkout";}
    else {
        print "Fatal -- invalid /repository value.\n";
        usage();
        die;
        }
    $switches[0]->{repository}->{value} = $rverb;   ## Save canonicalized repository verb.

    my $wd  = $src."\\pismere";

    if (! ($rverb =~ /skip/)) {
        local $len = 0;
        if (exists $fetch[0]->{USERNAME}->{name}) {
            $len = length $fetch[0]->{USERNAME}->{name};
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

# Begin logging:
    my $l;
    if ($switches[0]->{logfile}->{value}) {
        print "Info -- logging to $switches[0]->{logfile}->{path}.\n";
        $l = new Logger $switches[0]->{logfile}->{path};
        $l->start;
        $l->no_die_handler;        ## Needed so XML::Simple won't throw exceptions.
        }

##++ Begin repository action:
    if ($rverb =~ /skip/) {print "Info -- *** Skipping repository access.\n"    if ($verbose);}
    else {
        if ($verbose) {print "Info -- *** Begin fetching sources.\n";}
        if (! -d $wd) {                        ## xcopy will create the entire path for us.
            !system("echo foo > a.tmp")                     or die "Fatal -- Couldn't create temporary file in ".`cd`;
            !system("echo F | xcopy a.tmp $wd\\CVS\\a.tmp") or die "Fatal -- Couldn't xcopy to $wd\\CVS.";
            !system("rm a.tmp")                             or die "Fatal -- Couldn't remove temporary file.";
            !system("rm $wd\\CVS\\a.tmp")                   or die "Fatal -- Couldn't remove temporary file.";
            }
        
        # Set up cvs environment variables:
        $ENV{CVSROOT}   = $fetch[0]->{CVSROOT}->{name};
        chdir($src)                                         or die "Fatal -- couldn't chdir to $src\n";
        print "Info -- chdir to ".`cd`."\n"                 if ($verbose);
        my $krb5dir     = "$wd\\athena\\auth\\krb5";

        my $cvscmdroot  = "cvs $rverb";
        my $cvscmd      = $cvscmdroot;
        if ($rverb =~ /checkout/) {        
            my @cvsmodules    = (    
                'krb',  
                'pismere/athena/util/lib/delaydlls', 
                'pismere/athena/util/lib/getopt', 
                'pismere/athena/util/guiwrap'
                );

            foreach my $module (@cvsmodules) {
                $cvscmd = $cvscmdroot." ".$module;
                $cvscmd .= " ".$tags[0]->{cvs}->{value} if ($tags[0]->{cvs}->{value});
                if ($verbose) {print "Info -- cvs command: $cvscmd\n";}
                !system($cvscmd)                        or die "Fatal -- command \"$cvscmd\" failed; return code $?\n";
                }
            }
        else {                ## Update.
            $cvscmd = $cvscmdroot;
            $cvscmd .= " ".$tags[0]->{cvs}->{value}     if ($tags[0]->{cvs}->{value});
            if ($verbose) {print "Info -- cvs command: $cvscmd\n";}
            !system($cvscmd)                            or die "Fatal -- command \"$cvscmd\" failed; return code $?\n";
            }
                    
        # Set up svn environment variable:
        $ENV{SVN_SSH} = "plink.exe";
        # If  the directory structure doesn't exist, many cd commands will fail.
        if (! -d $krb5dir) {mkdir($krb5dir)             or die "Fatal -- Couldn't  create $krb5dir";}
        chdir($krb5dir)                                 or die "Fatal -- Couldn't chdir to $krb5dir";
        print "Info -- chdir to ".`cd`."\n"             if ($verbose);
        my $svncmd = "svn $rverb ";
        if ($rverb =~ /checkout/) {        # Append the rest of the checkout command:
            chdir("..");
            $svncmd .= "svn+ssh://".$fetch[0]->{USERNAME}->{name}."@".$fetch[0]->{SVNURL}->{name}."/krb5/trunk krb5";
            }
        if ($tags[0]->{svn}->{value}) {$svncmd .= " ".$tags[0]->{svn}->{value};}    # Add any specific tag
        if ($verbose) {print "Info -- svn command: $svncmd\n";}
        !system($svncmd)            or die "Fatal -- command \"$svncmd\" failed; return code $?\n";

        if ($verbose) {print "Info -- ***   End fetching sources.\n";}
        }
##-- End  repository action.
        
##++ Make action:
    if (    (!$switches[0]->{nomake}->{value}) ) {
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
        if (exists $config->{Stages}->{Make}->{Prunes}) {
            # Use Unix find instead of Windows find.  Save PATH so we can restore it when we're done:
            my $savedPATH    = $ENV{PATH};
            $ENV{PATH} = $config->{CommandLine}->{Directories}->{unixfind}->{path}.";".$savedPATH;
            my $prunes = $config->{Stages}->{Make}->{Prunes};
            my $j=0;
            print "Info -- Processing prunes in ".`cd`."\n"     if ($verbose);
print Dumper($prunes);
            while ($prunes->{Prune}->[$j]) {
                if (exists $prunes->{Prune}->[$j]->{name}) {    ## Don't process dummy entry!
                    my $prune    = $prunes->{Prune}->[$j]->{name};
                    my $flags    = $prunes->{Prune}->[$j]->{flags};
                    $flags = "" if (!$flags);
                    my $cmd    = "find . -".$flags."name $prune";
                    print "Info -- Looking for filenames containing $prune\n";
                    my $list = `$cmd`;
                    foreach $target (split("\n", $list)) {
                        print "Info -- Pruning $target\n" if ($verbose);
                        ! system("rm -rf $target")              or die "Unable to prune $target";
                        }
                    }
                $j++;
                }
            $ENV{PATH} = $savedPATH;
            }

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
        my $dbgswitch = ($switches[0]->{debug}->{value}) ? " " : "NODEBUG=1";
        !system("perl ../scripts/build.pl --softdirs --nolog $buildtarget $dbgswitch")    or die "Fatal -- build $buildtarget failed.";
            
        chdir("$wd")               or die "Fatal -- couldn't chdir to $wd.";
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
    if ($switches[0]->{nopackage}->{value}) {      ## If /clean, this switch will have been cleared.
        print "Info -- *** Skipping packaging.";
        }
    else {
        if ($verbose) {print "Info -- *** Begin prepackage.\n";}

        # We read in the version information to be able to update the site-local files in the install build areas:
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
        my $requirements_met = 1;
        my $first_missing = 0;
        my $error_list = "";
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
        
        # The build results are copied to a staging area, where the packager expects to find them.
        #  We put the staging area in the fixed area .../pismere/staging.
        my $prepackage  = $config->{Stages}->{PrePackage};
        my $staging     = "$wd\\staging";
        chdir($wd)                          or die "Fatal -- couldn't chdir to $wd\n";
        print "Info -- chdir to ".`cd`."\n" if ($verbose);
        !system("rm -rf $staging/*")        or die "Fatal -- Couldn't clean $staging.";
        !system("rmdir $staging")           or die "Fatal -- Couldn't remove $staging.";
        mkdir($staging)                     or die "Fatal -- Couldn't create $staging.";
        
        # Force Where From and To are relative to:
        $prepackage->{CopyList}->{Config}->{From}->{root}   = "$wd\\athena";
        $prepackage->{CopyList}->{Config}->{To}->{root}     = "$wd\\staging";
        copyFiles($prepackage->{CopyList}, $config);        ## Copy any files [this step takes a while]

        # Sign files:
        chdir($staging) or die "Fatal -- couldn't chdir to $staging\n";
        print "Info -- chdir to ".`cd`."\n"     if ($verbose);
        if ($switches[0]->{sign}->{value}) {
            signFiles($config->{Stages}->{PostPackage}->{Config}->{Signing}, $config);
            }
            
        chdir("$staging\\install\\wix") or die "Fatal -- Couldn't cd to $staging\\install\\wix";
        # Correct errors in files.wxi:
        !system("sed 's/WorkingDirectory=\"\\[dirbin\\]\"/WorkingDirectory=\"dirbin\"/g' files.wxi > a.tmp") or die "Fatal -- Couldn't modify files.wxi.";
        !system("mv a.tmp files.wxi") or die "Fatal -- Couldn't update files.wxi.";
            
        # Make sed script to run on the site-local configuration files:
        local $tmpfile      = "site-local.sed" ;
        system("del $tmpfile");
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
        !system("sed -f $tmpfile site-local-tagged.wxi > site-local.wxi")   or die "Fatal -- Couldn't modify site-local.wxi.";

        # Now update site-local.nsi:
        chdir "..\\nsis";
        print "Info -- chdir to ".`cd`."\n"                                 if ($verbose);
        !system("sed -f ..\\wix\\$tmpfile site-local-tagged.nsi > b.tmp")   or die "Fatal -- Couldn't modify site-local.wxi.";
        # Add DEBUG or RELEASE:
        if ($switches[0]->{debug}->{value}) {                               ## debug build
            !system("echo !define DEBUG >> b.tmp")                          or die "Fatal -- Couldn't modify b.tmp.";    
            }
        else {                                                              ## release build
            !system("echo !define RELEASE >> b.tmp")                        or die "Fatal -- Couldn't modify b.tmp.";    
            !system("echo !define NO_DEBUG >> b.tmp")                       or die "Fatal -- Couldn't modify b.tmp.";    
            }
        # Add BETA if present:
        if ( exists $config->{Versions}->{'BETA_STR'}) {
            !system("echo !define BETA $config->{Versions}->{'BETA_STR'} >> b.tmp") or die "Fatal -- Couldn't modify b.tmp.";    
            }
        !system("mv -f b.tmp site-local.nsi")                               or die "Fatal -- Couldn't replace site-local.nsi.";

        # Run the script on nsi-includes-tagged.nsi:
        !system("sed -f ..\\wix\\$tmpfile nsi-includes-tagged.nsi > nsi-includes.nsi")  or die "Fatal -- Couldn't modify nsi-includes.nsi.";

        if ($verbose) {print "Info -- ***   End prepackage.\n";}
        
        if ($verbose) {print "Info -- *** Begin package.\n";}
        # Make the msi:
        chdir("$wd\\staging\\install\\wix") or die "Fatal -- Couldn't cd to $wd\\staging\\install\\wix";
        print "Info -- *** Make .msi:\n"            if ($verbose);
        !system("$MAKE")                            or die "Error -- msi installer build failed.";
                
        chdir("$wd\\staging\\install\\nsis") or die "Fatal -- Couldn't cd to $wd\\staging\\install\\nsis";
        print "Info -- chdir to ".`cd`."\n"         if ($verbose);
        print "Info -- *** Make NSIS:\n"            if ($verbose);
        !system("cl.exe killer.cpp advapi32.lib")   or die "Error -- nsis killer.exe not built.";
        !system("rename killer.exe Killer.exe")     or die "Error -- Couldn't rename killer.exe";
        !system("makensis kfw.nsi")                 or die "Error -- executable installer build failed.";

# Begin packaging extra items:
        chdir($src);        # Now in <src>.
        print "Info -- chdir to ".`cd`."\n"         if ($verbose);
        if (-d $out)    {!system("rm -rf $out/*")   or die "Fatal -- Couldn't clean $out."}    ## Clean output directory.
        else            {mkdir($out);}
        my $zipsXML = $config->{Stages}->{PostPackage}->{Zips};

        local $i = 0;
            while ($zipsXML->{Zip}[$i]) {
                local $zip = $zipsXML->{Zip}[$i];
                makeZip($zip, $config)  if (exists $zip->{name});       ## Ignore dummy entry.
                chdir("$out");
                print "Info -- chdir to ".`cd`."\n" if ($verbose);
                system("rm -rf ziptemp")            if (-d "ziptemp");  ## Clean up any temp directory.
                $i++;                    
            }                                       ## End zip in xml.
                
        $config->{Stages}->{PostPackage}->{CopyList}->{Config} = $config->{Stages}->{PostPackage}->{Config};    ## Use the post package config.
        $config->{Stages}->{PostPackage}->{CopyList}->{Config}->{From}->{root}  = "$src\\pismere";
        $config->{Stages}->{PostPackage}->{CopyList}->{Config}->{To}->{root}    = "$out";
        copyFiles($config->{Stages}->{PostPackage}->{CopyList}, $config);       ## Copy any files

        print "Info -- chdir to ".`cd`."\n"     if ($verbose);
        if ($switches[0]->{sign}->{value}) {
            signFiles($config->{Stages}->{PostPackage}->{Config}->{Signing}, $config);
            }

        if ($verbose) {print "Info -- ***   End package.\n";}
        }
##-- Package action.

    system("rm -rf $src/a.tmp");                ## Clean up junk.
    system("rm -rf $out/a.tmp");                ## Clean up junk.
    system("rm -rf $out/ziptemp");              ## Clean up junk.
                
# End logging:
    if ($switches[0]->{logfile}->{value})   {$l->stop;}

    return 0;
    }                                           ## End subroutine main.

$SIG{'INT'} = \&handler;
$SIG{'QUIT'} = \&handler;

exit(main());