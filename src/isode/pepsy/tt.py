-- $Header$
--
--
-- $Log$
-- Revision 1.1  1994/06/10 03:31:48  eichin
-- autoconfed isode for kerberos work
--
# Revision 1.1  1994/05/31 20:40:40  eichin
# reduced-isode release from /mit/isode/isode-subset/src
#
-- Revision 8.0  91/07/17  12:43:18  isode
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



TT DEFINITIONS ::=

%{
int foo;
%}

BEGIN

EntryInformationSelection [[P struct entryinfoselection *]]
	::=
	SET
	{
	attributeTypes
		CHOICE [[ T struct entryinfoselection * $ *]]
		<D< (*parm)->eis_allattributes>>
		<E< parm->eis_allattributes ? 1 : 2>>
		{
		allAttributes
			[0] NULL,
		select
			[1] SET OF [[ T struct attrcomp * $ eis_select ]] <<attr_link>>
				AttributeType [[p attr_type]]
		}
		%D{
			if ((*parm)->eis_allattributes == 1)
			   (*parm)->eis_allattributes = TRUE;
			else
			   (*parm)->eis_allattributes = FALSE;
		%}
		    -- DEFAULT allAttributes NULL,
		    OPTIONAL <E<parm->eis_allattributes != FALSE>><D<0>>,
	infoTypes
		[2] INTEGER [[i eis_infotypes]]
		{
		attributeTypesOnly(0) ,
		attributeTypesAndValues(1)
		}
		    DEFAULT attributeTypesAndValues
	}


TestChoice ::= CHOICE <E< 1 >> <D< foo >> {
	one OCTET STRING,
	two SEQUENCE {
		one2 IA5String OPTIONAL <E< 1 >> <D< 0 >>,
		two2 CHOICE {
			one3 NULL,
			two3 INTEGER
		} OPTIONAL <E<1>> <D<foo = 1>>
	},
	three INTEGER {eine(1), zwei(2), drie(3) },
	four BIT STRING { un(1), deux(2), trois(3), quatre(4) }
}
END

