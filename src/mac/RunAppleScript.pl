use Mac::Components;
use Mac::OSA;
use Mac::AppleEvents;

undef $/;

$applescript = OpenDefaultComponent(kOSAComponentType, "ascr") or die "AppleScript not installed";
$script = AECreateDesc "TEXT", <STDIN>;

$result = OSADoScript($applescript, $script, 0, "TEXT", 0) or die $^E;

print AEPrint($result), "\n";

AEDisposeDesc $result;
AEDisposeDesc $script;
CloseComponent $applescript;
