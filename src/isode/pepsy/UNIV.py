-- ASN.1 UNIVERSAL defined types

--
-- 
--

--
--				  NOTICE
--
--    Acquisition, use, and distribution of this module and related
--    materials are subject to the restrictions of a license agreement.
--    Consult the Preface in the User's Manual for the full terms of
--    this agreement.
--
--


UNIV DEFINITIONS ::=

%{
%}

BEGIN


			-- ISO 646-1983
IA5String ::=
    [UNIVERSAL 22]
	IMPLICIT OCTET STRING

NumericString ::=
    [UNIVERSAL 18]
    	IMPLICIT IA5String

PrintableString	::=
    [UNIVERSAL 19]
	IMPLICIT IA5String


			-- ISO 6937/2-1983
T61String ::=
    [UNIVERSAL 20]
    	IMPLICIT OCTET STRING

TeletexString ::=
	T61String

			-- ISO 6937/2-1983
VideotexString ::=
    [UNIVERSAL 21]
	IMPLICIT OCTET STRING


			-- ISO 2014, 3307, 4031
			--     date, time, zone
GeneralizedTime	::=
    [UNIVERSAL 24]
    	IMPLICIT VisibleString

GeneralisedTime	::=
	GeneralizedTime


UTCTime ::=
    [UNIVERSAL 23]
    	IMPLICIT VisibleString

UniversalTime ::=
	UTCTime

			-- ISO 2375
GraphicString ::=
    [UNIVERSAL 25]
    	IMPLICIT OCTET STRING

VisibleString ::=
    [UNIVERSAL 26]
    	IMPLICIT OCTET STRING

ISO646String ::=
	VisibleString

GeneralString ::=
    [UNIVERSAL 27]
    	IMPLICIT OCTET STRING

CharacterString ::=
    [UNIVERSAL 28]
    	IMPLICIT OCTET STRING


			-- ISO 8824
EXTERNAL ::=
    [UNIVERSAL 8]
	IMPLICIT SEQUENCE {
	    direct-reference
		OBJECT IDENTIFIER
		OPTIONAL,

	    indirect-reference
		INTEGER
		--* OPTIONAL *-- DEFAULT 0,

	    data-value-descriptor
		ObjectDescriptor
		OPTIONAL,

	    encoding
		CHOICE {
		    single-ASN1-type[0]
			ANY,

		    octet-aligned[1]
			IMPLICIT OCTET STRING,

		    arbitrary[2]
			IMPLICIT BIT STRING
		}
	}


			-- ISO 8824
ObjectDescriptor ::=
    [UNIVERSAL 7]
    	IMPLICIT GraphicString

END

%{

#ifndef PEPSY_VERSION

PEPYPARM NullParm = (PEPYPARM) 0;

#endif

%}
