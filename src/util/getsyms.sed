# emulate a C preprocessor (well, sort of)
y/	/ /
s/  */ /g
/\/\*/{
:COMMENT
N
y/	/ /
s/  */ /g
/\*\//!bCOMMENT
}
s/\/\*.*\*\///
/^ *#ifdef/{
s/^ *#ifdef //
b
}
/^ *#ifndef/{
s/^ *#ifndef //
b
}
/^ *#if/{
s/^ *#if//
s/ *defined *( *\([A-Za-z0-9_]*\) *) */\1 /g
s/||//g
s/&&//g
s/!//g
s/(//g
s/)//g
b
}
d
