/*
 * prof_section.c --- routines that manipulate the profile_section_t
 * 	object
 *
 * XXX this file is still under construction.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#include "prof_int.h"

/*
 * This routine frees a profile_section
 */
void profile_free_section(sect)
	profile_section_t	sect;
{
	if (sect->name)
		free(sect->name);
	sect->magic = 0;
	free(sect);
}

/*
 * This routine creates a profile_section from its parent.  If the
 * parent is NULL, then a top-level profile section is created.
 *
 * Top-level profile sections are different from normal
 * profile_sections in that top-level sections are agregated across
 * multiple files, where as subsections are not.
 */
errcode_t profile_get_subsection(profile, parent, name, ret_name,
				 ret_section)
	profile_t		profile;
	profile_section_t	parent;
	const char *		name;
	char **			ret_name;
	profile_section_t	*ret_section;
{
	profile_section_t	section;
	prf_file_t		file;
	errcode_t		retval;

	section = malloc(sizeof(struct _profile_section_t));
	if (section == 0)
		return ENOMEM;
	memset(section, 0, sizeof(struct _profile_section_t));
	section->magic = PROF_MAGIC_SECTION;
	section->name = malloc(strlen(name)+1);
	if (section->name == 0) {
		free(section);
		return ENOMEM;
	}
	strcpy(section->name, name);
	section->file_ptr = file = profile->first_file;
	section->profile = profile;

	if (parent == 0) {
		/*
		 * If parent is NULL, then we are creating a
		 * top-level section which hangs off the root.
		 * 
		 * We make sure that the section exists in least one
		 * file.
		 */
		section->top_lvl = 1;
		if (name == 0)
			return PROF_TOPSECTION_ITER_NOSUPP;
		while (file) {
			retval = profile_find_node_subsection(file->root,
				name, &section->state,
			        ret_name, &section->sect);
			file = file->next;
			if (retval == 0)
				break;
			if (retval == PROF_NO_SECTION)
				continue;
			profile_free_section(section);
			return retval;
		}
		if (section->sect == 0 && file == 0) {
			profile_free_section(section);
			return PROF_NO_SECTION;
		}
		*ret_section = section;
		return 0;
	}
		
	
	section->top_lvl = 0;
	if (parent->top_lvl) {
		section->top_lvl_search = 1;
		
	} else {
		section->top_lvl_search = 0;
		if (parent->sect == 0) {
			profile_free_section(section);
			return PROF_INVALID_SECTION;
		}
		section->parent = parent->sect;
		retval = profile_find_node_subsection(parent->sect,
		      name, &section->state, ret_name, &section->sect);
		if (retval) {
			profile_free_section(section);
			return retval;
		}
	}
	*ret_section = section;
	return 0;
}

errcode_t profile_next_section(section, ret_name)
	profile_section_t	section;
	char			**ret_name;
{
	prf_file_t	file;
	errcode_t	retval;
	
	if (section->top_lvl)
		return PROF_END_OF_SECTIONS;
	else {
		if (section->sect == 0)
			return PROF_INVALID_SECTION;
		retval = profile_find_node_subsection(section->parent,
		    section->name, &section->state, ret_name, &section->sect);
		if (retval == PROF_NO_SECTION)
			retval = PROF_END_OF_SECTIONS;
		return retval;
	}
}

errcode_t profile_get_relation(section, name, ret_values)
	profile_section_t	section;
	const char 		*name;
	char 			***ret_values;
{
	prf_file_t	file;
	char		**values;
	int		num_values;
	int		max_values;
	char		*value;
	errcode_t	retval;
	

	max_values = 10;
	values = malloc(sizeof(char *) * max_values);
	
	if (section->top_lvl) {
		for (file = section->profile->first_file; file;
		     file = file->next) {
			retval = profile_find_node_relation(file->root,
			    section->name, &section->state, 0, &value);
			if (retval)
				continue;
			
		}
	} else {
		if (section->sect == 0)
			return PROF_INVALID_SECTION;
	}
	return 0;
}

	
	
