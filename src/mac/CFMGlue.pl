#!/usr/local/bin/perl -w

use strict; # Turn on careful syntax checking
use 5.002;  # Require Perl 5.002 or later

# Pre-declare globals, as required by "use strict"
use vars qw(%RESERVEDWORDS $file $prototype);

# C words which aren't a type or a parameter name
# [digit] is special cased later on...
%RESERVEDWORDS = (
		  const    => "const",
		  "*"      => "*",
		  "[]"     => "[]",
		  struct   => "struct",
		  enum     => "enum",
		  union    => "union",
		  unsigned => "unsigned",
		  register => "register"
		  );

# Read the entire file into $file
{
    local $/;
	undef $/; # Ignore end-of-line delimiters in the file
    $file .= <STDIN>;
}

# Remove the C and C++ comments from the file.
# If this regexp scares you, don't worry, it scares us too.
$file =~ s@/ # Both kinds of comment begin with a /
             # First, process /* ... */
            ((\*[^*]*\*+				  # 1: Identify /**, /***, /* foo *, etc.  
			  ([^/*][^*]*\*+)*			  # 2: Match nothing, x*, x/*, x/y*, x*y* etc. 
			 /)							  # 3: Look for the trailing /. If not present, back up
			 							  #    through the matches from step 2 (x*y* becomes x*)
										  #### if we get here, we have /* ... */
		   |  # Or, it's // and we just need to match to the end of the line
		   (/.*?\n))					  # 4. Slash, shortest possible run of characters ending in newline (\n)
		  @\n@xg;						  # => Replace match with a newline.
		  								  ###  "x" modifier allows whitespace and comments in patterns
										  ###  "g" modifier means "do this globally"

$file =~ tr! \t\n! !s; 			   		  # Convert newlines, tabs, and runs of spaces into single spaces

foreach $prototype (split /;/, $file) 	  # Break string apart at semicolons, pass each piece to our Convert routine
{
	Convert($prototype);
}

exit (0);

# ========================================
# Subroutines follow
# ========================================

sub Convert()
{
	# Take our special C-style function prototypes and print out the
	# appropriate glue code.
	
	my $prototype = shift;
	my ($returnType, $functionName, $paramString);
	my (@parameters, @types);
	
	return if ($prototype =~ /^\s*$/); 	   # Ignore blank lines
	# Use custom function to remove leading & trailing spaces & 
	# collapse runs of spaces.
	$prototype = StripSpaces($prototype);   
	
	# ====================
	# STAGE 1.1: Get the function name and return type.
	#            Do general syntax checking.
	# ====================
	
	# See if we have a legal prototype and begin parsing. A legal prototype has
	# a return type (optional), function name, and parameter list.
	unless ($prototype =~ /((\w+\*? )*(\w+\*?)) (\w+)\s*\((.*)\)$/)
	{
		die "Prototype \"$prototype;\" does not appear to be a legal prototype.\n";
	}
	
	# That unless had a nice side effect -- the parentheses in the regular expression
	# stuffed the matching parts of the expression into variables $1, $2, and $3.
	
	($returnType, $functionName) = ($1, $4);
	# Kill 2 birds at a time -- get rid of leading & trailing spaces *and* get an
	# empty string back if there are no parameters
	$paramString = StripSpaces($5);				
	
	# Insist on having an argument list in the prototype
	unless ($paramString)
	{
		die("Prototype: \"$prototype;\" has no arguments.\n" .
			 "This is ambiguous between C and C++ (please specify " .
			 "either (int) or (void)).\n");
	}
	
	# Check for variable arguments by looking for
	# "va_list <something>" or "..."
	if(($paramString =~ /va_list\s+\S+/) or # va_list + spaces + not-a-spaces
	   ($paramString =~ /\Q.../))			# \Q = "quote metacharacters" => \.\.\.
	{
		die("Prototype: \"$prototype;\" takes a variable " .  
			"number of arguments. Variable arguments are not " . 
			"supported by CFM Glue.\n");
	}

	# ====================
	# STAGE 1.2: Digest the parameter list.
	# ====================

	if ($paramString eq "void")
	{
		$parameters[0] = "void";
		$types[0] = "void";
	}
	else
	{
		# The function has nonvoid arguments
		
		# Add spaces around * and turn [#] into [#] with spaces around it
        # for ease of parsing
	    $paramString =~ s/\s*\*\s*/ \* /g;
	    $paramString =~ s/\s*\[(\d*)\]\s*/ [$1] /g;

		# Extract the list elements
		my @arguments = split /,\s*/, $paramString;
		
		# Make sure we don't have more than 13 arguments
		if ($#arguments >= 13)
		{
			die "Prototype \"$prototype;\" has more than 13 arguments,\n".
				"which the CFM68K glue will not support.";
		}
		
		# We need to look at each argument and come out with two lists: a list
		# of parameter names and a corresponding list of parameter types. For example:
		# ( const int x, short y[], int )
		# needs to become two lists:
		# @parameters = ("x", "y", "__param0")
		# @elements = ("const int", "short *", int)
		my $i = 0; # parameter counter
		foreach my $argument (@arguments)
		{
		    my @elements = split(' ', $argument);
			
			# A legal argument will have a name and/or a parameter type.
			# It might _also_ have some C keywords
			# We'll syntax check the argument by counting the number of things
			# which are names and/or variable types
			my $identifierCount = grep { !$RESERVEDWORDS{$_} && !/\[\d*\]/ } @elements;
			
			if ($identifierCount == 1) {
				# We have a type without a name, so generate an arbitrary unique name
				push @parameters, "__param" . $i;
			} 
			elsif ($identifierCount == 2) {
				# We have a type and a name. We'll assume the name is the last thing seen,
				my $paramName = pop @elements;
				# ...but have to make certain it's not a qualified array reference
				if ($paramName =~ /\[\d*\]/)
				{
			    	# Whoops...the argument ended in a [], so extract the name and put back
					# the array notation
					my $temp = $paramName;
					$paramName = pop @elements;
					push @elements, $temp;
				}
				push @parameters, $paramName;
			}
			else # $identifierCount == 0 or $identifierCount > 2
			{
			die("Prototype: \"$prototype;\" has an " .
			    "invalid number ($identifierCount)" . 
			    " of non-reserved words in argument '$argument'.\n");
			}
			
			# Replace all "[]" with "*" to turn array references into pointers.
			# "map" sets $_ to each array element in turn; modifying $_ modifies
			# the corresponding value in the array. (s -- substutition -- works
			# on $_ by default.)
			map { s/\[\d*\]/*/ } @elements;
			
			push @types, join(' ', @elements); # Construct a type definition
			
		    # Increment the argument counter:
		    $i++;
		}
	}

	# ====================
	# STAGE 2: Print out the glue.
	# ====================

	# Generate the ProcInfo Macro:
	# ----------------------------
	my $result = ""; # Will be inserted into the final macro
	if ($returnType ne "void") {
		$result = "\n  | RESULT_SIZE(SIZE_CODE(sizeof($returnType)))";
	}
	
	# Convert a list of parameter types into entries for the macro.
	# All non-void parameters need to have a line in the final macro.
	my @parameterMacros;
	my $paramCount = -1;
	@parameterMacros = map { $paramCount++; $_ eq "void" ? "" : 
							"  | STACK_ROUTINE_PARAMETER(" . ($paramCount + 1) . ", SIZE_CODE(sizeof($_)))" } @types;
	my $macroString = join "\n", @parameterMacros;
	
	print <<HEADER; # Print everything from here to the word HEADER below, returns and all
/**** $functionName ****/
/* $prototype; */

enum {
  ${functionName}_ProcInfo = kThinkCStackBased $result
$macroString
};


HEADER

	
	# Generate the ProcPtr Typedef
	# --------------------------------
	my $typeList = join ", ", @types;
	print "typedef $returnType (*${functionName}_ProcPtrType)($typeList);\n";
		
	
	# Generate the Static 68K Function Declaration:
	# -------------------------------------------------
	# Most of the complexity in this code comes from
	# pretty-printing the declaration
	
	my $functionDec = "$returnType $functionName (";
	my $fnArguments;
	if($types[0] eq "void")
	{
		$fnArguments = "void";
	}
	else
	{
		my @joinedList;
		# Merge the parameter and type lists together
		foreach my $i (0..$#types)
		{
			push @joinedList, ($types[$i] . ' ' . $parameters[$i]);
		}
		
		# Build a list of parameters where each parameter is aligned vertically
		# beneath the one above.
		# "' ' x 5" is a Perl technique to get a string of 5 spaces
		$fnArguments = join (",\n".(' ' x length($functionDec)), @joinedList);
	} 

	# Create a list of parameters to pass to the 68K function
	my $fnParams = "";
	if($types[0] ne "void") {
		$fnParams = join ", ", @parameters;
	}

	# Do we have an explicit return statement? This depends on the return type
	my $returnAction = " ";
	$returnAction = "return " if ($returnType ne "void");
	
	# The following code introduces a new Perl trick -- ${a} is the same as $a in a string
	# (interpolate the value of variable $a); the brackets are used to seperate the variable
	# name from the text immediately following the variable name so the Perl interpreter 
	# doesn't go looking for the wrong variable.
	print <<FUNCTION;
${functionDec}$fnArguments)
{
  static ${functionName}_ProcPtrType ${functionName}_ProcPtr = kUnresolvedCFragSymbolAddress;
	
  // if this symbol has not been setup yet...
  if((Ptr) ${functionName}_ProcPtr == (Ptr) kUnresolvedCFragSymbolAddress)
    FindLibrarySymbol((Ptr *) &${functionName}_ProcPtr, "\\p$functionName", ${functionName}_ProcInfo);
  if((Ptr) ${functionName}_ProcPtr != (Ptr) kUnresolvedCFragSymbolAddress)
    $returnAction ${functionName}_ProcPtr($fnParams);
}


FUNCTION

	# That's all!
}

sub StripSpaces()
{
	# Remove duplicate, leading, and trailing spaces from a string
	my $string = shift;
	return "" unless ($string);			# If it's undefined, return an empty string
	
	$string =~ tr! ! !s;   			    # remove duplicate spaces
	$string =~ s/\s*(\w.+)?\s*$/$1/;    # Strip leading and trailing spaces
	return $string;
}

