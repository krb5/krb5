#!perl -w

#use strict;
use FindBin;
use File::Spec;
use File::Basename;
use lib "$FindBin::Bin/build/lib";
#use Logger;
use Getopt::Long;
use Cwd;
use XML::Simple;
use Data::Dumper;
use Archive::Zip qw( :ERROR_CODES :CONSTANTS );
   
# my $zip = Zip->new();

my $BAIL;
$0 = fileparse($0);
my $OPT = { logfile => 'bkw.pl.log' };
my $MAKE = 'NMAKE';

sub get_info
    {
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
    /help /?      usage information (what you now see)
    /srcdir dir   Source directory to use.  Should contain 
                  pismere/athena.  If cvstag or svntag is null, 
                  the directory should be prepopulated.
    /cvstag tag   \\ For whichever of these tags is specified,
    /svntag url   / a checkout  will be done into srcdir
    /debug        Do debug make instead of release make
    /outdir dir   Directory to be created where build results will go
    /nomake       Skip make step
    /nopackage    Skip packaging step
    /clean        Build clean target
    /verbose      Debug mode - verbose output
    /config path  Path to config file
    /logfile path Where to write output.  If omitted, ...
  Other:
    NMAKE-options    any options you want to pass to NMAKE, which can be:
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

sub makeDir {
	my ($path) = @_;
	if (! -d $path) {
		mkdir($path) or die "Fatal -- couldn't create $path";
		print "Debug -- makeDir($path)\n";
		}
	else {print "Debug -- makeDir($path) -- directory already exists.\n";}
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
	       'clean',
	       'verbose',
	       'vverbose',
	       'nomake',
	       'nopackage',
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

# #print Dumper($OPT);
    
    # List of programs which must be in PATH:
    my @required_list = ('sed', 'awk', 'which', 'cat', 'rm', 'cvs', 'svn', 'doxygen', 'hhc', 'candle', 'light');
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
	my $originalDir =`cd`;
	$originalDir =~ s/\n//g;

    my $errorState = 0;		## Cumulative return code.  0 is success.

##++ Assemble configuration from config file and command line:

    my $configfile;
    $configfile = $OPT->{config};

    print "Info -- Reading configuration from $configfile.\n";

    # Get configuration file:
	my $xml = new XML::Simple();
	my $config = $xml->XMLin($configfile);

	# Set up convenience variables:
	my (@switches, @paths, @tags, @prepackage, @files);
	@switches		= $config->{CommandLine}->{Options};
	@paths			= $config->{CommandLine}->{Directories};
	@tags				= $config->{CommandLine}->{Tags};
	@prepackage	= $config->{Stages}->{PrePackage};
	@files				= $config->{Stages}->{PrePackage}->{CopyList}->{Files};

    # Update the config with overrides from the command line:
	$tags[0]->{cvs}->{value} = $OPT->{cvstag}					if exists $OPT->{cvstag};
	$tags[0]->{svn}->{value} = $OPT->{svnurl}					if exists $OPT->{svnurl};
	$paths[0]->{src}->{path} = $OPT->{srcdir}					if exists $OPT->{srcdir};
    $paths[0]->{out}->{path} = $OPT->{outdir}				if exists $OPT->{outdir};
    $switches[0]->{debug}->{value} = $OPT->{debug}	if exists $OPT->{debug};
    $switches[0]->{clean}->{value} = 1								if exists $OPT->{clean};
    $switches[0]->{nomake}->{value} = 1							if exists $OPT->{nomake};
    $switches[0]->{nopackage}->{value} = 1						if exists $OPT->{nopackage};
    $switches[0]->{verbose}->{value} = $OPT->{verbose}		if exists $OPT->{verbose};
    $switches[0]->{vverbose}->{value} = $OPT->{verbose}	if exists $OPT->{vverbose};
	if (exists $OPT->{logfile}) {
		$switches[0]->{log}->{path} = $OPT->{logfile};
		$switches[0]->{log}->{value} = 1;
		}
    my $verbose			= $config->{CommandLine}->{Options}->{verbose}->{value};
    my $vverbose		= $config->{CommandLine}->{Options}->{vverbose}->{value};

	if ($switches[0]->{clean}->{value} && !$switches[0]->{nopackage}->{value}) {
		print "Info -- /clean forces /nopackage.\n";
		$switches[0]->{nopackage}->{value} = 1;
		}

	my $i = 0;
	# See if there is an included file list:
	if (exists $files[0]->{Include}->{path}) {
		my $configfile2 = $files[0]->{Include}->{path};
		print "Info -- Including files to be copied from $configfile2.\n";
		my $config2 = $xml->XMLin($configfile2);
		while ($config2->{File}[$i]) {
			$files[0]->{File}[++$#{$files[0]->{File}}] = $config2->{File}[$i];
			$i++;
			}
		}
		
    if ($vverbose) {print Dumper($config);}
    
	# Examples of use:
	#print "Logfile path: $switches[0]->{log}->{path}\n";
	#print "src path: $paths[0]->{src}->{path}\n";
	#print "cvs tag: $tags[0]->{cvs}->{value}\n";
	#print "CVSROOT:   $config->{Config}->{CVSROOT}->{name}\n";

##-- Assemble configuration from config file and command line.

# Begin logging:
#    my $l;
#    if ($OPT->{logfile}) {
#		$l = new Logger $OPT->{logfile} or die "Fatal -- Can't create Logger.";
#		$l->start;
#		}

if (!$switches[0]->{nomake}->{value}) {
	if ($verbose) {print "Info -- *** Begin fetching sources.\n";}
	
	my ($wd, $result);
	$wd = $paths[0]->{src}->{path};
	chdir($wd) or die "Fatal -- couldn't chdir to $wd\n";
	if ($verbose) {print "Info -- chdir to $wd\n";}
	
	#if (! -d "pismere")					{print "Warning -- can't find pismere in $wd.  It will be created.\n";}
	#if (! -d "pismere\\athena")	{print "Warning -- can't find pismere\\athena in $wd.  It will be created.\n";}
	
	if ($tags[0]->{cvs}->{value})		{
		# Set up cvs environment variables:
		print "Warning -- cvs checkout skipped for now.\n";
	#	system("cvs checkout krb") or die "Fatal -- checkout of cvs source failed; return code $?\n";
		}
	else	{print "Info -- cvs tag not specified; no cvs sources will be checked out.\n";}
	
	if ($tags[0]->{svn}->{value})	{
		# Set up svn environment variables:
		print "Warning -- svn checkout skipped for now.\n";
	#	system("svn checkout krb") or die "Fatal -- checkout of svn source failed; return code $?\n";
		}
	else	{print "Info -- svn tag not specified; no svn sources will be checked out.\n";}
	
	if ($verbose) {print "Info -- ***   End fetching sources.\n";}
	
	if ($verbose) {print "Info -- *** Begin preparing for build.\n";}
	
	my ($path, $destpath);
	
	# Copy athena\scripts\site\graft\krb5\Makefile.src to athena\auth\krb5:
	$path = "pismere\\scripts\\site\\graft\\krb5\\Makefile.src";
	if (!-e  $path) {die "Fatal -- Expected file $wd\\$path not found.";}
	$destpath = "pismere\\athena\\auth\\krb5\\Makefile.src";
	!system("echo F | xcopy /D $wd\\$path $wd\\$destpath /Y > NUL") or die "Fatal -- Copy of $wd\\$path to $wd\\$destpath failed.";
	print "Info -- copied $wd\\$path to $wd\\$destpath\n";
	
	# Add DEBUG_SYMBOL to .../wshelper/Makefile.src:
	$path = "pismere\\athena\\wshelper\\wshelper\\Makefile.src";
	if (!-e  $path) {die "Fatal -- Expected file $wd\\$path not found.";}
	if (system("grep DEBUG_SYMBOL $path > NUL") != 0) {
		!system ("echo DEBUG_SYMBOL=1 >> $wd\\$path") or die "Fatal -- Append line to file failed.\n";
		print "Info -- Added DEBUG_SYMBOL to $wd\\$path\n";
		}
	
	if ($verbose) {print "Info -- ***   End preparing for build.\n";}
	
	my ($buildtarget, $buildtext);
	if ($switches[0]->{clean}->{value}) {
		$buildtarget = "clean" ;
		$buildtext = " clean."
		}
	else {
		$buildtarget = "" ;
		$buildtext = "."
		}
	if ($verbose) {print "Info -- *** Begin build".$buildtext."\n";}
	
	chdir("pismere/athena") or die "Fatal -- couldn't chdir to source directory $wd\\pismere\\athena\n";
	if ($verbose) {print "Info -- chdir to $wd\\pismere\\athena\n";}
		!system("perl ../scripts/build.pl --softdirs $buildtarget")	or die "Fatal -- build $buildtarget failed.";
		
	chdir("..") or die "Fatal -- couldn't chdir to $wd\\pismere.";
	if ($switches[0]->{clean}->{value}) {
		if (-d "staging") {
			!system("rm -rf staging") or die "Fatal -- Couldn't remove pismere/staging.";
			}
		}

	if ($verbose) {print "Info -- ***   End build".$buildtext."\n";}
	}				## End make conditional.
	
if (!$switches[0]->{nopackage}->{value}) {
	if ($verbose) {print "Info -- *** Begin prepackage.\n";}
	
	# The build results are copied to a staging area, where the packager expects to find them.
	#  We put the staging area in the fixed area .../pismere/staging.
	$wd = $paths[0]->{src}->{path}."\\pismere";
	my $staging_area = "$wd\\staging";
	chdir($wd) or die "Fatal -- couldn't chdir to $wd\n";
	if ($verbose) {print "Info -- chdir to $wd\n";}
	(-e $staging_area) or makeDir($staging_area);
	
	my $src = $paths[0]->{src}->{path};
	my $CopyList			= $prepackage[0]->{CopyList};
	
	# A path can contain a variable part, which will be handled here.  If the variable part is 
	# the Always or BuildDependent tag, then the variable will be changed to the 
	# build-type-dependent PathFragment.
	# If the variable part is the IgnoreTag, then the file will not be copied.
	my ($PathFragment, $BuildDependentTag, $IgnoreTag); 

	my $AlwaysTag				= $CopyList->{Config}->{AlwaysTag}->{value};
	if ($switches[0]->{debug}->{value}) {		## Debug build tags:
		$PathFragment				= $CopyList->{Config}->{DebugArea}->{value};
		$BuildDependentTag	= $CopyList->{Config}->{DebugTag}->{value};
		$IgnoreTag					= $CopyList->{Config}->{ReleaseTag}->{value};
		}
	else {																## Release build tags:
		$PathFragment				= $CopyList->{Config}->{ReleaseArea}->{value};
		$BuildDependentTag	= $CopyList->{Config}->{ReleaseTag}->{value};
		$IgnoreTag					= $CopyList->{Config}->{DebugTag}->{value};
		}			

	# Copy all the files in the CopyList:
	$i = 0;
	my $nfiles = 0;
	while ($files[0]->{File}[$i]) {
		my ($name, $newname, $from, $to, $ignore);
		$name		= $files[0]->{File}->[$i]->{name};
		if (exists $files[0]->{File}->[$i]->{newname})	{$newname = $files[0]->{File}->[$i]->{newname};}
		else																				{$newname = $name;}
		if ($name) {
			$ignore = 0;
			$from	= "$src\\pismere\\athena\\$files[0]->{File}->[$i]->{from}\\$name";
			$to		= "$src\\pismere\\staging\\$files[0]->{File}->[$i]->{to}\\$newname";
			if (index($from.$to, $IgnoreTag) <0) {					## Test for IgnoreTag
				# Apply PathTag substitutions:
				$from	=~ s/$AlwaysTag/$PathFragment/g;
				$to		=~ s/$AlwaysTag/$PathFragment/g;
				$from	=~ s/$BuildDependentTag/$PathFragment/g;
				$to		=~ s/$BuildDependentTag/$PathFragment/g;
				# We use xcopy instead of copy because it will create directories for us:
				if (system("echo F | xcopy /D /F /Y $from $to 2>NUL") != 0) {
					# xcopy failed.  
					if (!exists $files[0]->{File}->[$i]->{notrequired}) {
						( -e $from) or die "Fatal -- can't find $from";
						die "Fatal -- Copy of $from to $to failed";
						}
					}
				else {$nfiles++;}
				}
			}
		$i++;
		}
		
	# Copy the extras:
	print "Info -- Absent a way of scripting unzip, the instructions require manually unzipping into\n";
	print "        the target area $src\\pismere\\staging.\n";
	# my $extradir = $paths[0]->{extras}->{path};
	# !system("xcopy /d/f/y/s $src\\pismere\\athena\\$extradir\\* $src\\pismere\\staging") or die "Fatal -- Couldn't copy extras from $src\\pismere\\athena\\$extradir";
	
	chdir("staging\\install\\wix") or die "Fatal -- Couldn't cd to $wd\\staging\\install\\wix";
	
	# Correct errors in files.wxi:
	!system("sed 's/WorkingDirectory=\"\\[dirbin\\]\"/WorkingDirectory=\"dirbin\"/g' files.wxi > a.tmp") or die "Fatal -- Couldn't modify files.wxi.";
	!system("copy /y a.tmp files.wxi") or die "Fatal -- Couldn't update files.wxi.";
	!system("del a.tmp") or print "Warning -- Couldn't clean up temporary file $wd\\staging\\installer\\wix\\a.tmp.\n";
		
	# Update paths in site-local.wxi:
	my $dblback_originalDir = $originalDir;
	$dblback_originalDir =~ s/\\/\\\\/g;
	!system("sed -f $dblback_originalDir\\site-local.sed site-local.wxi > b.tmp") or die "Fatal -- Couldn't modify site-local.wxi.";
	my $hexback_wd = $wd;
	$hexback_wd =~ s/\\/\\\\\\\\\\\\/g;
	!system("sed 's/%%TARGETDIR%%/$hexback_wd\\\\\\staging\\\\\\/' b.tmp > c.tmp") or die "Fatal -- Couldn't modify site-local.wxi temporary file.";	
	!system("sed 's/%%CONFIGDIR%%/$hexback_wd\\\\\\staging\\\\\\sample\\\\\\/' c.tmp > d.tmp") or die "Fatal -- Couldn't modify site-local.wxi temporary file.";	
	!system("copy /y d.tmp site-local.wxi") or die "Fatal -- Couldn't replace site-local.wxi.";

	# Copy krb.conf from ...\athena\auth\krb5\src\config-files	to pismere\staging\samples\krb5.ini:
	!system("echo F | xcopy /D $wd\\athena\\auth\\krb5\\src\\config-files\\krb5.conf $wd\\staging\\sample\\krb5.ini") 
		or die "Fatal -- Couldn't update $wd\\staging\\sample\\krb5.ini.";

	# Sam said to leave these files out, but it is faster to copy them now 
	#  than to figure out how to modify the wix configs to ignore them:
	!system("echo F | xcopy /D $wd\\staging\\kfw-2.5-extra\\sample-config\\*.con $wd\\staging\\sample") 
		or die "Fatal -- Couldn't copy $wd\\staging\\kfw-2.5-extra\\sample-config\\*.con.";

	if ($verbose) {print "Info -- ***   End prepackage.\n";}
	
	# Make the msi:
	!system("nmake") or die "Fatal -- Couldn't make kfw.msi.";

	if ($verbose) {print "Info -- *** Begin package.\n";}
	if ($verbose) {print "Info -- ***   End package.\n";}
	}						## End package conditional.
	
#End logging:
#    if (!$OPT->{nolog}) {
#		$l->stop;
#		}

    return $errorState;
}

$SIG{'INT'} = \&handler;
$SIG{'QUIT'} = \&handler;

##exit (0);
exit(main());