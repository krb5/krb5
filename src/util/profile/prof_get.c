/*
 * prof_get.c --- routines that expose the public interfaces for
 * 	querying items from the profile.
 *
 * A profile object can contain multiple profile files; each profile
 * is composed of hierarchical sections.  Sections can contain
 * sections, or relations, both of which are named.  (Sections roughly
 * correspond to directories, and relations to files.)
 * 
 * Relations may contain multiple values; profile_get_values() will
 * return all of the values for a particular relation,
 * profile_get_value() will return the first such value for a
 * relation.
 *
 * When there are multiple profile files open for a particular
 * profile object, the searching algorithms will find the first
 * profile file which contains the full section-path, and only look in
 * that profile file for the named relation.
 *
 * An example here may be useful.  Consider a profile which is
 * initialied to search to profile files, ~/.samplerc and
 * /etc/sample.conf, in that order.  Let us suppose that the
 * system-wide /etc/sample.conf contains the following information:
 *
 * [realms]
 *	ATHENA.MIT.EDU = {
 * 		kdc = kerberos.mit.edu:88
 * 		kdc = kerberos-1.mit.edu:88
 * 		kdc = kerberos-2.mit.edu:88
 * 		admin_server = kerberos.mit.edu:88
 * 		default_domain = mit.edu
 * 	}
 *
 * [DNS]
 * 	MIT.EDU = {
 * 		strawb = {
 * 			version = 4.8.3
 * 			location = E40
 * 		}
 * 		bitsy = {
 * 			version = 4.8.3
 * 			location = E40
 * 		}
 * 	}
 *
 * ... and the user's ~/.samplerc contains the following:
 *
 * [realms]
 * 	ATHENA.MIT.EDU = {
 * 		kdc = kerberos-test.mit.edu
 * 		admin_server = kerberos-test.mit.edu
 * 	}
 *
 * [DNS]
 * 	MIT.EDU = {
 * 		w20-ns = {
 * 			version = 4.8.3
 * 			location = W20
 * 		}
 * 		bitsy = {
 * 			version = 4.9.4
 * 		}
 * 	}
 * 
 * In this example, the values for realms/ATHENA.MIT.EDU/kdc and
 * realms/ATHENA.MIT.EDU/admin_server will be taken from ~/.samplrc
 * exclusively, since the section realms/ATHENA.MIT.EDU was found
 * first in ~/.samplerc.
 * 
 * However, in the case of the [DNS] section, queries for
 * DNS/MIT.EDU/w20-ns/<*> will be taken from ~/.samplrc, and
 * DNS/MIT.EDU/strawb/<*> will be taken from /etc/sample.rc.
 * 
 * DNS/MIT.EDU/BITSY/version will return 4.9.4, since the entry
 * in ~/.samplerc will override the one in /etc/sample.conf.  Less
 * intuitively, a query for DNS/bitsy/location will return no value,
 * since the DNS/bitsy section exists in ~/.samplerc.
 * 
 * This can all be summed up using the following rule: a section found
 * in an earlier profile file completely shadows a section in a later
 * profile file for the purposes of looking up relations, but not when
 * looking up subsections contained in the section.
 * 
 */

#include <stdio.h>
#include <string.h>
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#include <errno.h>

#include "prof_int.h"

/*
 * These functions --- init_list(), end_list(), and add_to_list() are
 * internal functions used to build up a null-terminated char ** list
 * of strings to be returned by functions like profile_get_values.
 *
 * The profile_string_list structure is used for internal booking
 * purposes to build up the list, which is returned in *ret_list by
 * the end_list() function.
 *
 * The publicly exported interface for freeing char** list is
 * profile_free_list().
 */

struct profile_string_list {
	char	**list;
	int	num;
	int	max;
};

/*
 * Initialize the string list abstraction.
 */
static errcode_t init_list(list)
	struct profile_string_list *list;
{
	list->num = 0;
	list->max = 10;
	list->list = malloc(list->max * sizeof(char *));
	if (list->list == 0)
		return ENOMEM;
	list->list[0] = 0;
	return 0;
}

/*
 * Free any memory left over in the string abstraction, returning the
 * built up list in *ret_list if it is non-null.
 */
static void end_list(list, ret_list)
    struct profile_string_list *list;
    char ***ret_list;
{
	char	**cp;

	if (list == 0)
		return;

	if (ret_list) {
		*ret_list = list->list;
		return;
	} else {
		for (cp = list->list; *cp; cp++)
			free(*cp);
		free(list->list);
	}
	list->num = list->max = 0;
	list->list = 0;
}

/*
 * Add a string to the list.
 */
static errcode_t add_to_list(list, str)
	struct profile_string_list *list;
	const char	*str;
{
	char 	*newstr, **newlist;
	int	newmax;
	
	if (list->num+1 >= list->max) {
		newmax = list->max + 10;
		newlist = realloc(list->list, newmax * sizeof(char *));
		if (newlist == 0)
			return ENOMEM;
		list->max = newmax;
		list->list = newlist;
	}
	newstr = malloc(strlen(str)+1);
	if (newstr == 0)
		return ENOMEM;
	strcpy(newstr, str);

	list->list[list->num++] = newstr;
	list->list[list->num] = 0;
	return 0;
}

/*
 * Return TRUE if the string is already a member of the list.
 */
static int is_list_member(list, str)
	struct profile_string_list *list;
	const char	*str;
{
	char **cpp;

	if (!list->list)
		return 0;

	for (cpp = list->list; *cpp; cpp++) {
		if (!strcmp(*cpp, str))
			return 1;
	}
	return 0;
}	
	
/*
 * This function frees a null-terminated list as returned by
 * profile_get_values.
 */
KRB5_DLLIMP void KRB5_CALLCONV profile_free_list(list)
    char	**list;
{
    char	**cp;

    if (list == 0)
	    return;
    
    for (cp = list; *cp; cp++)
	free(*cp);
    free(list);
}

/*
 * This function searches the profile for a named section, looking in
 * each file in the profile.  If ret_name is NULL, then this
 * function looks at the entire names array; if ret_name is non-NULL,
 * then the last entry in the names array is assumed to be the name of
 * the relation desired by profile_get_values(), and is returned in
 * ret_name.  The section looked up in that case will not include the
 * last entry in the names array.
 */
static errcode_t lookup_section(profile, names, ret_name, ret_section)
	profile_t	profile;
	const char	**names;
	const char	**ret_name;
	struct profile_node **ret_section;
{
	prf_file_t	file;
	errcode_t	retval;
	int		done_idx = 0;
	const char	**cpp;
	void		*state;
	struct profile_node *section;

	if (profile == 0)
		return PROF_NO_PROFILE;

	if (names == 0 || names[0] == 0 || (ret_name && names[1] == 0))
		return PROF_BAD_NAMESET;

	if (ret_name)
		done_idx = 1;

	file = profile->first_file;
	if ((retval = profile_update_file(file)))
		return retval;

	section = file->root;
	cpp = names;

	while (cpp[done_idx]) {
		state = 0;
		retval = profile_find_node_subsection(section, *cpp,
						      &state, 0, &section);
		if (retval == PROF_NO_SECTION) {
			/*
			 * OK, we didn't find the section in this
			 * file; let's try the next file.
			 */
			file = file->next;
			if (!file)
				return retval;
			if ((retval = profile_update_file(file)))
				return retval;
			section = file->root;
			cpp = names;
			continue;
		} else if (retval)
			return retval;
		cpp++;
	}
	*ret_section = section;
	if (ret_name)
		*ret_name = *cpp;
	return 0;
}

/*
 * This function finds a relation from the profile, and returns all of
 * the values from that relation.  
 */
KRB5_DLLIMP errcode_t KRB5_CALLCONV
profile_get_values(profile, names, ret_values)
	profile_t	profile;
	const char	**names;
	char	***ret_values;
{
	errcode_t		retval;
	struct profile_node 	*section;
	void			*state;
	const char		*name;
	char			*value;
	struct profile_string_list values;

	retval = lookup_section(profile, names, &name, &section);
	if (retval)
		return retval;

	init_list(&values);

	state = 0;
	do {
		if ((retval = profile_find_node_relation(section, name,
							 &state, 0, &value)))
			goto cleanup;
		add_to_list(&values, value);
	} while (state);

	end_list(&values, ret_values);
	return 0;
	
cleanup:
	end_list(&values, 0);
	return retval;
}	

/*
 * This function only gets the first value from the file; it is a
 * helper function for profile_get_string, profile_get_integer, etc.
 */
static errcode_t profile_get_value(profile, names, ret_value)
	profile_t	profile;
	const char	**names;
	char	**ret_value;
{
	errcode_t		retval;
	struct profile_node 	*section;
	void			*state;
	const char		*name;
	char			*value;

	retval = lookup_section(profile, names, &name, &section);
	if (retval)
		return retval;

	state = 0;
	if ((retval = profile_find_node_relation(section, name,
						 &state, 0, &value)))
		return retval;
	
	*ret_value = value;
	return 0;
}

errcode_t profile_get_string(profile, name, subname, subsubname,
			     def_val, ret_string)
	profile_t	profile;
	const char	*name, *subname, *subsubname;
	const char	*def_val;
	char 	**ret_string;
{
	const char	*value;
	errcode_t	retval;
	const char	*names[4];

	if (profile) {
		names[0] = name;
		names[1] = subname;
		names[2] = subsubname;
		names[3] = 0;
		retval = profile_get_value(profile, names, &value);
		if (retval == PROF_NO_SECTION || retval == PROF_NO_RELATION)
			value = def_val;
		else if (retval)
			return retval;
	} else
		value = def_val;
    
	if (value) {
		*ret_string = malloc(strlen(value)+1);
		if (*ret_string == 0)
			return ENOMEM;
		strcpy(*ret_string, value);
	} else
		*ret_string = 0;
	return 0;
}

errcode_t profile_get_integer(profile, name, subname, subsubname,
			      def_val, ret_int)
	profile_t	profile;
	const char	*name, *subname, *subsubname;
	int		def_val;
	int		*ret_int;
{
	char	*value;
	errcode_t	retval;
	const char	*names[4];

	if (profile == 0) {
		*ret_int = def_val;
		return 0;
	}

	names[0] = name;
	names[1] = subname;
	names[2] = subsubname;
	names[3] = 0;
	retval = profile_get_value(profile, names, &value);
	if (retval == PROF_NO_SECTION || retval == PROF_NO_RELATION) {
		*ret_int = def_val;
		return 0;
	} else if (retval)
		return retval;
   
	*ret_int = atoi(value);
	return 0;
}

/*
 * This function will return the list of the names of subections in the
 * under the specified section name.
 */
errcode_t profile_get_subsection_names(profile, names, ret_names)
	profile_t	profile;
	const char	**names;
	char		***ret_names;
{
	prf_file_t	file;
	errcode_t	retval;
	char		*name;
	const char	**cpp;
	void		*state;
	struct profile_node *section;
	struct profile_string_list values;

	if (profile == 0)
		return PROF_NO_PROFILE;

	if (names == 0)
		return PROF_BAD_NAMESET;

	init_list(&values);
	for (file = profile->first_file; file; file = file->next) {
		if ((retval = profile_update_file(file)))
			return retval;
		section = file->root;
		cpp = names;
		/*
		 * Find the correct section in this file, if it
		 * exists.
		 */
		while (*cpp) {
			state = 0;
			retval = profile_find_node_subsection(section, *cpp,
						      &state, 0, &section);
			if (retval == PROF_NO_SECTION)
				continue;
			else if (retval)
				goto cleanup;
			cpp++;
		}
		/*
		 * Now find all of the subsections and append them to
		 * the list.
		 */
		state = 0;
		do {
			retval = profile_find_node_subsection(section, 0, 
						      &state, &name, 0);
			if (retval == PROF_NO_SECTION)
				break;
			else if (retval)
				goto cleanup;
			if (!is_list_member(&values, name))
				add_to_list(&values, name);
		} while (state);
	}
	
	end_list(&values, ret_names);
	return 0;
cleanup:
	end_list(&values, 0);
	return retval;
}

/*
 * This function will return the list of the names of relations in the
 * under the specified section name.
 */
errcode_t profile_get_relation_names(profile, names, ret_names)
	profile_t	profile;
	const char	**names;
	char		***ret_names;
{
	errcode_t		retval;
	struct profile_node 	*section;
	void			*state;
	char			*name;
	struct profile_string_list values;

	retval = lookup_section(profile, names, 0, &section);
	if (retval)
		return retval;

	init_list(&values);

	state = 0;
	do {
		retval = profile_find_node_relation(section, 0,
						    &state, &name, 0);
		if (retval == PROF_NO_RELATION)
			break;
		else if (retval)
			goto cleanup;
		if (!is_list_member(&values, name))
			add_to_list(&values, name);
	} while (state);

	end_list(&values, ret_names);
	return 0;
cleanup:
	end_list(&values, 0);
	return retval;
}



