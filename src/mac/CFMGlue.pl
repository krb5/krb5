#!/usr/athena/bin/perl -w

%RESERVEDWORDS = (
		  const  => "const",
		  "*"    => "*",
		  "[]"   => "[]",
		  struct => "struct",
		  enum   => "enum",
		  union  => "union"
		  );

while(<STDIN>)
{
    chop($_);
    $prototype = $_;
    @splitup = split(/\s*\(\s*/, $prototype);
    
    # the return value type and the function name:
    $temp = $splitup[0];
    $temp =~ s/\s*\*\s*/ \* /g;         # add spaces around *
    @funcAndArgs = split(/\s+/, $temp);
    $functionName = $funcAndArgs[$#funcAndArgs];
    
    # Is this function already in the Hash Table?
    if(!exists($FUNCTIONS{$functionName}))
    {
	$FUNCTIONS{$functionName}{prototypeText} = $prototype;
	pop @{funcAndArgs};
	$FUNCTIONS{$functionName}{returnType} = join(' ', @funcAndArgs);
		
	# the arguments:
	@splitup2 = split(/\s*\)\s*/, $splitup[1]);
	@argsAndParams = split(/\s*,\s*/, $splitup2[0]);
		
	for($i = 0, $j = 1; $i <= $#argsAndParams; $i++, $j++)
	{
	    $temp = $argsAndParams[$i];
	    $temp =~ s/\s*\*\s*/ \* /g;         # add spaces around *
	    $temp =~ s/\s*\[\]\s*/ \[\] /g;     # add spaces around []

	    @elements = split(/\s+/, $temp);

            # Is there a parameter name in this argument?
	    $identifierCount = 0;
	    foreach $element (@elements)
	    {
		if(!exists($RESERVEDWORDS{$element})) {
		    $identifierCount++;
		}
	    }
	    
	    if(($identifierCount > 2) or ($identifierCount < 1)) {
		print("************** $argsAndParams ****************");
		die;
	    }

	    if($identifierCount >= 2) {
		$param = $elements[$#elements];
		pop(@elements);
		if($param eq "[]") {
		    $param = $elements[$#elements];
		    pop(@elements);
		    push(@elements, '*');
		}
		$type = join(' ', @elements);
	    } else {
		$type = $argsAndParams[$i];
		$param = "param" . $j;
	    }
	    $FUNCTIONS{$functionName}{typeList}[$i] = $type;
	    $FUNCTIONS{$functionName}{paramList}[$i] = $param;
	}
    }
}

foreach $function (keys(%FUNCTIONS))
{
    # the variables we will be playing with:
    $name      = $function;
    $retType   = $FUNCTIONS{$function}{returnType};
    $prototype = $FUNCTIONS{$function}{prototypeText};
    @args      = @{ $FUNCTIONS{$function}{typeList} };
    @params    = @{ $FUNCTIONS{$function}{paramList} };
    

    # Now Generate the ProcInfo Macro:
    # --------------------------------
    print("/**** $name ****/\n");
    print("/* $prototype */\n\n");
    
    print("enum {\n");
    print("  $name" . "_ProcInfo = kThinkCStackBased\n");
    if($retType ne "void") {
	print("  | RESULT_SIZE(SIZE_CODE(sizeof($retType)))\n");
    }
    for($i = 0, $j = 1; $i <= $#args; $i++, $j++)
    {
	$arg = $args[$i];
	print("  | STACK_ROUTINE_PARAMETER($j, SIZE_CODE(sizeof($arg)))\n");
    }    
    print("};\n\n");
    
    # Now Generate the ProcPtr Typedef
    # --------------------------------
    print("typedef ");
    print("$retType ");
    print("(*$name" . "_ProcPtrType)(");
    
    for($i = 0; $i<=$#args; $i++) {
	    $arg = $args[$i];
	    print("$arg");
	    if ($i ne $#args) {
	    	print (", ");
	    }
    }
    print(");\n");
  
    
    # Now Generate the Static 68K Function Declaration:
    # -------------------------------------------------
    print("$retType $name (\n");
    for($i = 0; $i <= $#args; $i++)
    {
	for($j = 0; $j <= length($retType); $j++) {	
	    print(" ");
	}
	print($args[$i] . ' ' . $params[$i]);
	if($i >= $#args) {
	    print(")\n");
	} else {
	    print(",\n");
	}
    } 
    print("{\n");
    print("  static $name" . "_ProcPtrType $name" . "_ProcPtr = kUnresolvedCFragSymbolAddress;\n\n");

    print("  // if this symbol has not been setup yet...\n");
    print("  if((Ptr) $name" . "_ProcPtr == (Ptr) kUnresolvedCFragSymbolAddress)\n");
    print("    Find_Symbol((Ptr *) &" . $name . "_ProcPtr, ");
    print("\"\\p" . $name . "\", $name" . "_ProcInfo);\n");
    print("  if((Ptr) $name" . "_ProcPtr != (Ptr) kUnresolvedCFragSymbolAddress)\n");
    if($retType ne "void") {
	print("    return $name" . "_ProcPtr(");
    } else {
	print("    $name" . "_ProcPtr(");
    }	    
    for($i = 0; $i <= $#args; $i++)
    {
	print($params[$i]);
	if($i >= $#args) {
	    print(");\n");
	} else {
	    print(", ");
	}
    } 
    
    print("}\n\n\n");
}
