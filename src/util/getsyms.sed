# emulate a C preprocessor (well, sort of)
y/	/ /
s/  */ /g
/\/\*/{
	:COMMENT
	y/	/ /
	s/  */ /g
	/\*\//!{
		N
		bCOMMENT
	}
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
/^ *#if.*defined/{
	s/^ *#if //
	:IF
	/^defined/!{
		:NUKE
		s/^.//
		/^defined/!bNUKE
	}
	h
	/^defined/s/^defined *( *\([A-Za-z0-9_]*\) *).*/\1/p
	g
	/^defined/s/^defined *( *\([[A-Za-z0-9_]*\) *)//
	/defined/!{
		d
		b
	}
	bIF
}
d
