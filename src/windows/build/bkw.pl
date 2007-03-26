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

my $BAIL;
$0 = fileparse($0);
my $OPT = {foo => 'bar'};
my $MAKE = 'NMAKE';
our $config;

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
    /help /?        usage information (what you now see).
    /config path    Path to config file.
    /srcdir dir     Source directory to use.  Should contain 
                    pismere/athena.  If cvstag or svntag is null, 
                    the directory should be prepopulated.
    /outdir dir     Directory to be created where build results will go
    /repository checkout | co \\  What repository action to take.
	        update   | up  ) Options are to checkout, update or 
	        skip          /  take no action [skip].
    /kerberos_id id kerberos id used to access svn if checking out.
    /cvstag tag   \\ If non-empty, the tag is appended to cvs and svn
    /svntag tag   / commands to select the rev to fetch.
    /debug          Do debug make instead of release make.
    /nomake         Skip make step.
    /clean          Build clean target.
    /nopackage      Skip packaging step.
    /verbose        Debug mode - verbose output.
    /logfile path   Where to write output.  If omitted, ...
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
	       'repository:s',
	       'kerberos_id:s',
	       'verbose',
	       'vverbose',
	       'nomake',
	       'clean',
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

    # List of programs which must be in PATH:
    my @required_list = ('sed', 'awk', 'which', 'cat', 'rm', 'cvs', 'svn', 'doxygen', 'hhc', 'candle', 'light', 'makensis', 'nmake');
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
	@switches		= $config->{CommandLine}->{Options};
	@paths			= $config->{CommandLine}->{Directories};
	@tags				= $config->{CommandLine}->{Tags};
	@fetch			= $config->{Stages}->{FetchSources}->{Config};

    # Update the configuration with overrides from the command line:
	$tags[0]->{cvs}->{value} = $OPT->{cvstag}								if exists $OPT->{cvstag};
	$tags[0]->{svn}->{value} = $OPT->{svnurl}								if exists $OPT->{svnurl};
	$paths[0]->{src}->{path} = $OPT->{srcdir}								if exists $OPT->{srcdir};
    $paths[0]->{out}->{path} = $OPT->{outdir}							if exists $OPT->{outdir};
    $switches[0]->{debug}->{value} = $OPT->{debug}				if exists $OPT->{debug};
    $switches[0]->{clean}->{value} = 1											if exists $OPT->{clean};
    $switches[0]->{repository}->{value} = $OPT->{repository}	if exists $OPT->{repository};
    $fetch[0]->{KERBEROS_ID}->{name} = $OPT->{kerberos_id}	if exists $OPT->{kerberos_id};
    $switches[0]->{nomake}->{value} = 1										if exists $OPT->{nomake};
    $switches[0]->{nopackage}->{value} = 1									if exists $OPT->{nopackage};
    $switches[0]->{verbose}->{value} = $OPT->{verbose}			if exists $OPT->{verbose};
    $switches[0]->{vverbose}->{value} = $OPT->{verbose}		if exists $OPT->{vverbose};
	if (exists $OPT->{logfile}) {
		$switches[0]->{logfile}->{path} = $OPT->{logfile};
		$switches[0]->{logfile}->{value} = 1;
		}
    our $verbose		= $config->{CommandLine}->{Options}->{verbose}->{value};
    our $vverbose		= $config->{CommandLine}->{Options}->{vverbose}->{value};
    our $clean				= $switches[0]->{clean}->{value};
	my $src					= $paths[0]->{src}->{path};

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
	if		($sw =~ /skip/i)			{$rverb = "skip";}
	elsif	($sw =~ /update/i)		{$rverb = "update";}
	elsif	($sw =~ /up/i)				{$rverb = "update";}
	elsif	($sw =~ /checkout/i)	{$rverb = "checkout";}
	elsif	($sw =~ /co/i)				{$rverb = "checkout";}
	else {
			print "Fatal -- invalid /repository value.\n";
			usage();
			die;
			}

	my $wd 	= $src."\\pismere";

	if ($rverb =~ /checkout/) {
		if (-d $wd) {
			print "\n\nHEADS UP!!\n\n";
			print "/REPOSITORY CHECKOUT will cause everything under $wd to be deleted.\n";
			print "If this is not what you intended, here's your chance to bail out!\n\n\n";
			print "Are you sure you want to remove everything under $wd? ";
			my $char = getc;
			if (! ($char =~ /y/i)) {die "Info -- operation aborted by user."}
			!system("rm -rf $wd/*")						or die "Fatal -- Couldn't clean $wd.";
			!system("rmdir $wd")							or die "Fatal -- Couldn't remove $wd.";
			}
		if (! -d $src)				{mkdir $src				or die "Fatal -- Couldn't create $src.";}
		if (! -d $wd)				{mkdir $wd				or die "Fatal -- Couldn't create $wd.";}
		if (! -d "$wd//CVS")	{mkdir "$wd//CVS"	or die "Fatal -- Couldn't create $wd\\CVS.";}
		}

# Begin logging:
    my $l;
    if ($switches[0]->{logfile}->{value}) {
		print "Info -- logging to $switches[0]->{logfile}->{path}.\n";
		$l = new Logger $switches[0]->{logfile}->{path};
		$l->start;
		$l->no_die_handler;		## Needed so XML::Simple won't throw exceptions.
		}

##++ Begin repository action:
	if ($rverb =~ /skip/) {print "Info -- *** Skipping repository access.\n"	if ($verbose);}
	else {
		if ($verbose) {print "Info -- *** Begin fetching sources.\n";}

		# Set up cvs environment variables:
		$ENV{CVSROOT} = $fetch[0]->{CVSROOT}->{name};
		chdir($src)												or die "Fatal -- couldn't chdir to $src\n";
		print "Info -- chdir to ".`cd`."\n"			if ($verbose);
		my $krb5dir	= $wd."\\athena\\auth\\krb5";

		my $cvscmdroot	= "cvs $rverb";
		my $cvscmd			= $cvscmdroot;
		if ($rverb =~ /checkout/) {		
			my @cvsmodules	= (	
				'krb',  
				'pismere/athena/util/lib/delaydlls', 
				'pismere/athena/util/lib/getopt', 
				'pismere/athena/util/guiwrap'
				);

			foreach my $module (@cvsmodules) {
				$cvscmd = $cvscmdroot." ".$module;
				$cvscmd .= " ".$tags[0]->{cvs}->{value}	if ($tags[0]->{cvs}->{value});
				if ($verbose) {print "Info -- cvs command: $cvscmd\n";}
				!system($cvscmd)							or die "Fatal -- command \"$cvscmd\" failed; return code $?\n";
				}
			}
		else {				## Update.
			$cvscmd = $cvscmdroot;
			$cvscmd .= " ".$tags[0]->{cvs}->{value}	if ($tags[0]->{cvs}->{value});
			if ($verbose) {print "Info -- cvs command: $cvscmd\n";}
			!system($cvscmd)								or die "Fatal -- command \"$cvscmd\" failed; return code $?\n";
			}
					
		# Set up svn environment variables:
		my $dblback_plink	= $fetch[0]->{KRB_PLINK}->{name};
		$dblback_plink =~ s/\\/\\\\/g;
		$ENV{SVN_SSH} = $dblback_plink;
		# If  the directory structure doesn't exist, many cd commands will fail.
		mkdir($krb5dir);
		chdir($krb5dir)											or die "Fatal -- couldn't chdir to $krb5dir\n";
		print "Info -- chdir to ".`cd`."\n"			if ($verbose);
		my $svncmd = "svn $rverb ";
		if ($rverb =~ /checkout/) {		# Append the rest of the checkout command:
			chdir("..");
			$svncmd .= "svn+ssh://".$fetch[0]->{KERBEROS_ID}->{name}."@".$fetch[0]->{SVNURL}->{name}."/krb5/trunk krb5";
			}
		if ($tags[0]->{svn}->{value}) {$svncmd .= " ".$tags[0]->{svn}->{value};}	# Add any specific tag
		if ($verbose) {print "Info -- svn command: $svncmd\n";}
		!system($svncmd)			or die "Fatal -- command \"$svncmd\" failed; return code $?\n";

		if ($verbose) {print "Info -- ***   End fetching sources.\n";}
		}
##-- End  repository action.
		
	if (	(!$switches[0]->{nomake}->{value}) ) {
		if ($verbose) {print "Info -- *** Begin preparing for build.\n";}

		$wd = $paths[0]->{src}->{path};
		chdir("$wd") or die "Fatal -- couldn't chdir to $wd\n";
		print "Info -- chdir to ".`cd`."\n"				if ($verbose);
	
		my ($path, $destpath);
		
		# Copy athena\scripts\site\graft\krb5\Makefile.src to athena\auth\krb5:
		$path = "pismere\\scripts\\site\\graft\\krb5\\Makefile.src";
		if (!-e  $path) {die "Fatal -- Expected file $wd\\$path not found.";}
		$destpath = "pismere\\athena\\auth\\krb5\\Makefile.src";
		!system("echo F | xcopy /D $wd\\$path $wd\\$destpath /Y > NUL") or die "Fatal -- Copy of $wd\\$path to $wd\\$destpath failed.";
		print "Info -- copied $wd\\$path to $wd\\$destpath\n"		if ($verbose);;
		
		# Add DEBUG_SYMBOL to .../wshelper/Makefile.src:
		$path = "pismere\\athena\\wshelper\\wshelper\\Makefile.src";
		if (!-e  $path) {die "Fatal -- Expected file $wd\\$path not found.";}
		if (system("grep DEBUG_SYMBOL $path > NUL") != 0) {
			!system ("echo DEBUG_SYMBOL=1 >> $wd\\$path") or die "Fatal -- Append line to file failed.\n";
			print "Info -- Added DEBUG_SYMBOL to $wd\\$path\n"	if ($verbose);
			}
		
		# Prune any unwanted directories before the build:
		if (exists $config->{Stages}->{Make}->{Prunes}) {
			# Use Unix find instead of Windows find.  Save PATH so we can restore it when we're done:
			my $savedPATH	= $ENV{PATH};
			$ENV{PATH} = $config->{CommandLine}->{Directories}->{unixfind}->{path}.";".$savedPATH;
			my $prunes = $config->{Stages}->{Make}->{Prunes};
			my $j=0;
			print "Info -- Processing prunes in ".`cd`."\n" if ($verbose);
			while ($prunes->{Prune}->[$j]) {
				if (exists $prunes->{Prune}->[$j]->{name}) {						## Don't process dummy entry!
					my $prune	= $prunes->{Prune}->[$j]->{name};
					my $flags	= $prunes->{Prune}->[$j]->{flags};
					$flags = "" if (!$flags);
					my $cmd	= "find . -".$flags."name $prune";
					print "Info -- Looking for filenames containing $prune\n";
					my $list = `$cmd`;
					foreach $target (split("\n", $list)) {
						print "Info -- Pruning $target\n" if ($verbose);
						! system("rm -rf $target")				or die "Unable to prune $target";
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
			$buildtext = " clean."
			}
		else {
			$buildtarget = "" ;
			$buildtext = "."
			}
		
		chdir("pismere/athena") or die "Fatal -- couldn't chdir to source directory $wd\\pismere\\athena\n";
		if ($verbose) {print "Info -- chdir to $wd\\pismere\\athena\n";}
			!system("perl ../scripts/build.pl --softdirs $buildtarget")	or die "Fatal -- build $buildtarget failed.";
			
		chdir("$wd\\pismere") or die "Fatal -- couldn't chdir to $wd\\pismere.";
		if ($clean) {
			if (-d "staging") {
				!system("rm -rf staging") or die "Fatal -- Couldn't remove pismere/staging.";
				}
			}
	
		if ($verbose) {print "Info -- ***   End build".$buildtext."\n";}
		}				## End make conditional.
	else {print "Info -- *** Skipping build.\n"	if ($verbose);}
		
	if (!$switches[0]->{nopackage}->{value}) {		## If /clean, this switch will have been cleared.
		if ($verbose) {print "Info -- *** Begin prepackage.\n";}
		# The build results are copied to a staging area, where the packager expects to find them.
		#  We put the staging area in the fixed area .../pismere/staging.
		my $prepackage	= $config->{Stages}->{PrePackage};
		$wd = $paths[0]->{src}->{path}."\\pismere";
		my $staging_area = "$wd\\staging";
		chdir($wd) or die "Fatal -- couldn't chdir to $wd\n";
		if ($verbose) {print "Info -- chdir to $wd\n";}
		(-e $staging_area) or mkdir($staging_area);
		
		# Force Where From and To are relative to:
		$prepackage->{CopyList}->{Config}->{From}->{root}		= "$src\\pismere\\athena";
		$prepackage->{CopyList}->{Config}->{To}->{root}			= "$src\\pismere\\staging";
		copyFiles($prepackage->{CopyList}, $config);		## Copy any files

		chdir("staging\\install\\wix") or die "Fatal -- Couldn't cd to $wd\\staging\\install\\wix";
		print "Info -- chdir to ".`cd`."\n"										if ($verbose);
		# Correct errors in files.wxi:
		!system("sed 's/WorkingDirectory=\"\\[dirbin\\]\"/WorkingDirectory=\"dirbin\"/g' files.wxi > a.tmp") or die "Fatal -- Couldn't modify files.wxi.";
		!system("mv a.tmp files.wxi") or die "Fatal -- Couldn't update files.wxi.";
			
		# Update paths in site-local.wxi:
		my $dblback_originalDir = $originalDir;
		$dblback_originalDir =~ s/\\/\\\\/g;
		!system("sed -f $dblback_originalDir\\site-local.sed site-local.wxi > b.tmp") or die "Fatal -- Couldn't modify site-local.wxi.";
		my $hexback_wd = $wd;
		$hexback_wd =~ s/\\/\\\\\\\\\\\\/g;
		!system("sed 's/%%TARGETDIR%%/$hexback_wd\\\\\\staging\\\\\\/' b.tmp > c.tmp")							or die "Fatal -- Couldn't modify site-local.wxi temporary file.";	
		!system("sed 's/%%CONFIGDIR%%/$hexback_wd\\\\\\staging\\\\\\sample\\\\\\/' c.tmp > d.tmp")	or die "Fatal -- Couldn't modify site-local.wxi temporary file.";	
		!system("mv d.tmp site-local.wxi")																														or die "Fatal -- Couldn't replace site-local.wxi.";
				
		if ($verbose) {print "Info -- ***   End prepackage.\n";}
		
		if ($verbose) {print "Info -- *** Begin package.\n";}
		# Make the msi:
		chdir("$wd\\staging\\install\\wix") or die "Fatal -- Couldn't cd to $wd\\staging\\install\\wix";
		print "Info -- *** Make .msi:\n"							if ($verbose);
		!system("$MAKE")													or die "Error -- msi installer build failed.";
				
		chdir("$wd\\staging\\install\\nsis") or die "Fatal -- Couldn't cd to $wd\\staging\\install\\nsis";
		print "Info -- chdir to ".`cd`."\n"						if ($verbose);
		print "Info -- *** Make NSIS:\n"							if ($verbose);
		!system("cl.exe killer.cpp advapi32.lib")			or die "Error -- nsis killer.exe not built.";
		!system("rename killer.exe Killer.exe")				or die "Error -- Couldn't rename killer.exe";
		!system("makensis kfw.nsi")								or die "Error -- executable installer build failed.";

# Begin packaging extra items:
		my $fromRoot	= $paths[0]->{src}->{path};
		my $toRoot		= $paths[0]->{out}->{path};
		chdir($fromRoot);		# Now in <src>.
		print "Info -- chdir to ".`cd`."\n"										if ($verbose);
		system("rm -rf $toRoot")													if (-d $toRoot);
		die "Fatal -- Couldn't remove $fromRoot\\$toRoot."	if (-d $toRoot);
		mkdir($toRoot);
		my $zipsXML = $config->{Stages}->{PostPackage}->{Zips};

		$config->{Stages}->{PostPackage}->{CopyList}->{Config}->{From}->{root}		= "$src\\pismere";		## Used after zips are made.
		$config->{Stages}->{PostPackage}->{CopyList}->{Config}->{To}->{root}			= "$src\\$toRoot\\ziptemp";
		my $filestem		= $config->{Stages}->{PostPackage}->{Config}->{FileStem}->{name};

		local $i = 0;
		while ($zipsXML->{Zip}[$i]) {
			my $zip = $zipsXML->{Zip}[$i];
			if (exists $zip->{name}) {												## Ignore dummy entry.
				my $zipname	= $zip->{filename};
				$zipname			=~ s/%filestem%/$filestem/g;
				my $bMakeIt		= 1;
				if (exists $zip->{Requires}) {
					local $j = 0;
					while ($zip->{Requires}->{Switch}[$j]) {				## Check Require switches
						local $switch	= $zip->{Requires}->{Switch}[$j];
						if (exists $switch->{name}) {								## Ignore dummy entry
							# We handle REPOSITORY and CLEAN switches:
							if ($switch->{name} =~ /REPOSITORY/i) {
								$bMakeIt &&= ($switch->{value} =~ /$rverb/i);	## Repository verb must match requirement
								}
							elsif ($switch->{name} =~ /CLEAN/i) {		## Clean must be specified
								$bMakeIt &&= $clean;
								}
							else {print "Error -- Unsupported switch $switch->{name} in Requires in ".Dumper($zip);}
							}
						$j++;
						}
					if ( !$bMakeIt && (exists $zip->{Requires}->{ErrorMsg}) ) {
						print "Error -- $zip->{Requires}->{ErrorMsg}->{text}\n";
						}
					}
				if ($bMakeIt) {
					my $todir			= "$src\\$toRoot\\ziptemp";
					system("rm -rf $todir")								if (-d $todir);
					die "Fatal -- Couldn't remove $todir"		if (-d $todir);
					mkdir($todir);
#	Add to the zip's config section.  Don't copy Postpackage->Config, because the Zip's Config might contain substitution tags.
					$zip->{CopyList}->{Config}->{FileStem}				= $config->{Stages}->{PostPackage}->{Config}->{FileStem};		## Each zip uses the post package config.
					$zip->{CopyList}->{Config}->{From}->{root}		= "$src\\pismere";								## Used by zips
					$zip->{CopyList}->{Config}->{To}->{root}			= "$src\\$toRoot\\ziptemp\\$zip->{topdir}";
					copyFiles($zip->{CopyList}, $config);
					# Drop down into <out>/ziptemp so the path to the added file won't include <out>:
					chdir $todir;
					print "Info -- chdir to ".`cd`."\n"				if ($verbose);

					# Prune any unwanted files or directories from the directory we're about to zip:
					if (exists $zip->{Prunes}) {
						# Use Unix find instead of Windows find.  Save PATH so we can restore it when we're3 done:
						my $savedPATH	= $ENV{PATH};
						$ENV{PATH} = $config->{CommandLine}->{Directories}->{unixfind}->{path}.";".$savedPATH;
						my $prunes = $zip->{Prunes};
						my $j=0;
						print "Info -- Processing prunes in ".`cd`."\n" if ($verbose);
						while ($prunes->{Prune}->[$j]) {
							if (exists $prunes->{Prune}->[$j]->{name}) {						## Don't process dummy entry!
								my $prune	= $prunes->{Prune}->[$j]->{name};
								my $flags	= $prunes->{Prune}->[$j]->{flags};
								$flags = "" if (!$flags);
								my $cmd	= "find . -".$flags."name $prune";
								print "Info -- Looking for filenames containing $prune\n";
								my $list = `$cmd`;
								foreach $target (split("\n", $list)) {
									print "Info -- Pruning $target\n" if ($verbose);
									!system("rm -rf $target")			or die "Error -- Couldn't remove $target.";;
									}
								}
							$j++;
							}
						$ENV{PATH} = $savedPATH;
						}

					my $zipfile			= Archive::Zip->new();
					my $topdir		= $zip->{topdir};
					$topdir				=~ s/%filestem%/$filestem/g;
					$zipfile->addTree('.', $topdir);
					if (-e $zipname)	{!system("rm -f $zipname")	or die "Error -- Couldn't remove $zipname.";}
					$zipfile->writeToFileNamed($zipname);
					print "Info -- created $src\\$toRoot\\$zipname.\n"	if ($verbose);
					!system("mv -f $zipname	 ..")					or die "Error -- Couldn't move $zipname to ..";
					chdir "..";						## Back to <out>
					print "Info -- chdir to ".`cd`."\n"				if ($verbose);
					}						## End else OK to process zip
				}							## End not the dummy entry
				$i++;					
			}								## End zip in xml.
				
		$todir	= "$src\\$toRoot\\ziptemp";					## Clean up any temp directory.
		system("rm -rf $todir")											if (-d $todir);
				
		my $out		= $config->{CommandLine}->{Directories}->{out}->{path};
		$config->{Stages}->{PostPackage}->{CopyList}->{Config} = $config->{Stages}->{PostPackage}->{Config};		## Use the post package config.
		$config->{Stages}->{PostPackage}->{CopyList}->{Config}->{From}->{root}		= "$src\\pismere";
		$config->{Stages}->{PostPackage}->{CopyList}->{Config}->{To}->{root}			= "$src\\$out";
		copyFiles($config->{Stages}->{PostPackage}->{CopyList}, $config);			## Copy any files
		if ($verbose) {print "Info -- ***   End package.\n";}
		}
	else {
		print "Info -- Package step skipped.";
		}

	system("rm -rf $src/a.tmp");									## Clean up junk.
				
# End logging:
    if ($switches[0]->{logfile}->{value})	{$l->stop;}

    return 0;
	}							## End subroutine main.

$SIG{'INT'} = \&handler;
$SIG{'QUIT'} = \&handler;

exit(main());