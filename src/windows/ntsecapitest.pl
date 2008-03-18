#!perl -w

$filename = "ntsecapitest.i";
$string = "VISTA_SDK_VERSION";

if (system("grep $string $filename")) {
    print "$string not found; deleting $filename.\n";
    system("rm $filename");
    }

exit(0);