/*
 * prof_init.c --- routines that manipulate the user-visible profile_t
 * 	object.
 */

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>

#include "prof_int.h"

errcode_t profile_init(filenames, ret_profile)
	const char **filenames;
	profile_t *ret_profile;
{
	const char **fn;
	profile_t profile;
	prf_file_t  new_file, last = 0;
	errcode_t retval;

	profile = malloc(sizeof(struct _profile_t));
	if (!profile)
		return ENOMEM;
	memset(profile, 0, sizeof(struct _profile_t));
	profile->magic = PROF_MAGIC_PROFILE;

	for (fn = filenames; *fn; fn++) {
		retval = profile_open_file(*fn, &new_file);
		if (retval) {
			profile_release(profile);
			return retval;
		}
		if (last)
			last->next = new_file;
		else
			profile->first_file = new_file;
		last = new_file;
	}
	*ret_profile = profile;
	return 0;
}

void profile_release(profile)
	profile_t	profile;
{
	prf_file_t	p, next;

	for (p = profile->first_file; p; p = next) {
		next = p->next;
		profile_close_file(p);
	}
	profile->magic = 0;
	free(profile);
}

struct string_list {
	char	**list;
	int	num;
	int	max;
};

static errcode_t init_list(list)
	struct string_list *list;
{
	list->num = 0;
	list->max = 10;
	list->list = malloc(list->max * sizeof(char *));
	if (list->list == 0)
		return ENOMEM;
	list->list[0] = 0;
	return 0;
}

static void free_list(list)
    struct string_list *list;
{
    char	**cp;
    
    for (cp = list->list; *cp; cp++)
	free(*cp);
    free(list->list);
    list->num = list->max = 0;
    list->list = 0;
}

static errcode_t add_to_list(list, str)
	struct string_list *list;
	const char	*str;
{
	char *newstr;
	
	if (list->num+1 >= list->max) {
		list->max += 5;
		list->list = realloc(list->list, list->max * sizeof(char *));
		if (list->list == 0)
			return ENOMEM;
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
 * XXX this version only works to get values from the first file.
 * To do more than that means we have to implement some "interesting"
 * code to do the section searching.
 */
errcode_t profile_get_values(profile, names, ret_values)
    profile_t	profile;
    const char	**names;
    char		***ret_values;
{
    prf_file_t	file;
    errcode_t	retval;
    struct profile_node *section;
    void		*state;
    char		*value;
    struct string_list values;
    const char		**cpp;

    if (names == 0 || names[0] == 0 || names[1] == 0)
	return PROF_BAD_NAMESET;

    init_list(&values);

    file = profile->first_file;
    section = file->root;

    for (cpp = names; cpp[1]; cpp++) {
	state = 0;
	retval = profile_find_node_subsection(section, *cpp,
					      &state, 0, &section);
	if (retval)
	    goto cleanup;
    }

    state = 0;
    do {
	retval = profile_find_node_relation(section, *cpp, &state, 0, &value);
	if (retval)
	    goto cleanup;
	add_to_list(&values, value);
    } while (state);

    *ret_values = values.list;
    return 0;
cleanup:
    free_list(&values);
    return retval;
}	

/*
 * XXX this version only works to get values from the first file.
 */
static errcode_t profile_get_value(profile, names, ret_value)
    profile_t	profile;
    const char	**names;
    char	**ret_value;
{
    prf_file_t	file;
    errcode_t	retval;
    struct profile_node *section;
    void		*state;
    char		*value;
    const char		**cpp;

    if (names == 0 || names[0] == 0 || names[1] == 0)
	return PROF_BAD_NAMESET;

    file = profile->first_file;
    section = file->root;

    for (cpp = names; cpp[1]; cpp++) {
	state = 0;
	retval = profile_find_node_subsection(section, *cpp,
					      &state, 0, &section);
	if (retval)
	    goto cleanup;
    }

    state = 0;
    retval = profile_find_node_relation(section, *cpp, &state, 0, &value);
    if (retval)
	goto cleanup;

    *ret_value = value;
    return 0;
cleanup:
    return retval;
}

errcode_t profile_get_string(profile, names, def_val, ret_string)
    profile_t	profile;
    const char	**names;
    const char	*def_val;
    char 	**ret_string;
{
    const char	*value;
    errcode_t	retval;

    retval = profile_get_value(profile, names, &value);
    if (retval == PROF_NO_SECTION || retval == PROF_NO_RELATION)
	value = def_val;
    else if (retval)
	return retval;
    
    *ret_string = malloc(strlen(value)+1);
    if (*ret_string == 0)
	return ENOMEM;
    strcpy(*ret_string, value);
    return 0;
}

errcode_t profile_get_integer(profile, names, def_val, ret_int)
    profile_t	profile;
    const char	**names;
    int		def_val;
    int		*ret_int;
{
   char	*value;
   errcode_t	retval;

   retval = profile_get_value(profile, names, &value);
   if (retval == PROF_NO_SECTION || retval == PROF_NO_RELATION) {
       *ret_int = def_val;
       return 0;
   } else if (retval)
       return retval;
   
   *ret_int = atoi(value);
   return 0;
}
