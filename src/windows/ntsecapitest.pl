#!perl -w

# We need to search ntsecapitest.i for "VISTA_SDK_VERSION."  If the makefile
#  greps and the string isn't present, the makefile will terminate.  Instead,
#  the makefile calls this helper, which either leaves a file behind or 
#  deletes it, depending on the grep result.  Then the makefile tests for 
#  file existence.

$filename = "ntsecapitest.i";
$string = "VISTA_SDK_VERSION";

# Without this command, the following grep will fail even when the target
#  string is present.
print `ls -l ntsecapitest.* > NULL`."\n";

if (system("grep $string $filename > NULL")) {
    system("rm $filename");
    }

exit(0);
