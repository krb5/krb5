-- $Header$
--
--
-- $Log$
-- Revision 1.1  1994/06/10 03:31:40  eichin
-- autoconfed isode for kerberos work
--
# Revision 1.1  1994/05/31 20:40:34  eichin
# reduced-isode release from /mit/isode/isode-subset/src
#
-- Revision 8.0  91/07/17  12:43:17  isode
-- Release 7.0
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



T2 DEFINITIONS ::=


BEGIN

-- Embedded Sequences test


SECTIONS enc dec prnt

Info ::= SEQUENCE {
	a1 [0] IMPLICIT INTEGER,
	a2 [1] IMPLICIT INTEGER,
	a3 [2] IMPLICIT INTEGER,
	a4 MPDU 
	}

MPDU ::=
	SEQUENCE {
	    a-seq SEQUENCE {
		fred [0] IMPLICIT INTEGER

	    }
	}

-- Simple type optimisations of POSY/PEPY

 Bstring ::= [APPLICATION 8] BIT STRING

 Ostring ::= [31] IMPLICIT OCTET STRING

 Obj ::= [101] IMPLICIT MPDU

 Sset ::= SET

 Sseq ::= SEQUENCE

 Sany ::= ANY

 Soid ::= OBJECT IDENTIFIER

END
