/*
 * prof_init.c --- routines that manipulate the user-visible profile_t
 * 	object.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#include "prof_int.h"

/* Find a 4-byte integer type */
#if	(SIZEOF_SHORT == 4)
typedef short	prof_int32;
#elif	(SIZEOF_INT == 4)
typedef int	prof_int32;
#elif	(SIZEOF_LONG == 4)
typedef	int	prof_int32;
#else	/* SIZEOF_LONG == 4 */
error(do not have a 4-byte integer type)
#endif	/* SIZEOF_LONG == 4 */

errcode_t profile_init(filenames, ret_profile)
	const char **filenames;
	profile_t *ret_profile;
{
	const char **fn;
	profile_t profile;
	prf_file_t  new_file, last = 0;
	errcode_t retval;

	initialize_prof_error_table();
	
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

    if (profile == 0)
	return PROF_NO_PROFILE;

    if (names == 0 || names[0] == 0 || names[1] == 0)
	return PROF_BAD_NAMESET;

    init_list(&values);

    file = profile->first_file;
    retval = profile_update_file(file);
    if (retval)
	goto cleanup;
    
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
 * To do more than that means we have to implement some "interesting"
 * code to do the section searching.
 */
errcode_t profile_get_first_values(profile, names, ret_values)
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
    char			*dummyvalue;
    char			*secname;
    const char			*mynames[3];
    

    if (profile == 0)
	return PROF_NO_PROFILE;

    if (names == 0 || names[0] == 0)
	return PROF_BAD_NAMESET;

    init_list(&values);

    file = profile->first_file;
    retval = profile_update_file(file);
    if (retval)
	goto cleanup;
    
    section = file->root;

    state = 0;
	retval = profile_find_node_subsection(section, *names, &state, &secname, &section);

    do {
	retval = profile_find_node_name(section, &state, &value);
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
    retval = profile_update_file(file);
    if (retval)
	goto cleanup;
    
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

errcode_t profile_ser_size(unused, profile, sizep)
    const char *unused;
    profile_t	profile;
    size_t	*sizep;
{
    size_t	required;
    prf_file_t	pfp;

    /*
     * ARGH - We want to avoid having to include k5-int.h.  We ASSuME that
     * krb5_int32 is 4 bytes in length.
     *
     * krb5_int32 for header
     * krb5_int32 for number of files.
     * krb5_int32 for trailer
     */
    required = 3*sizeof(prof_int32);
    for (pfp = profile->first_file; pfp; pfp = pfp->next) {
	required += sizeof(prof_int32);
	if (pfp->filename)
	    required += strlen(pfp->filename);
    }
    *sizep += required;
    return 0;
}

static void pack_int32(oval, bufpp, remainp)
    prof_int32		oval;
    unsigned char	**bufpp;
    size_t		*remainp;
{
    (*bufpp)[0] = (unsigned char) ((oval >> 24) & 0xff);
    (*bufpp)[1] = (unsigned char) ((oval >> 16) & 0xff);
    (*bufpp)[2] = (unsigned char) ((oval >> 8) & 0xff);
    (*bufpp)[3] = (unsigned char) (oval & 0xff);
    *bufpp += sizeof(prof_int32);
    *remainp -= sizeof(prof_int32);
}

errcode_t profile_ser_externalize(unused, profile, bufpp, remainp)
    const char		*unused;
    profile_t		profile;
    unsigned char	**bufpp;
    size_t		*remainp;
{
    errcode_t		retval;
    size_t		required;
    unsigned char	*bp;
    size_t		remain;
    prf_file_t		pfp;
    prof_int32		fcount, slen;

    required = 0;
    bp = *bufpp;
    remain = *remainp;
    retval = EINVAL;
    if (profile) {
	retval = ENOMEM;
	(void) profile_ser_size(unused, profile, &required);
	if (required <= remain) {
	    fcount = 0;
	    for (pfp = profile->first_file; pfp; pfp = pfp->next)
		fcount++;
	    pack_int32(PROF_MAGIC_PROFILE, &bp, &remain);
	    pack_int32(fcount, &bp, &remain);
	    for (pfp = profile->first_file; pfp; pfp = pfp->next) {
		slen = (pfp->filename) ?
		    (prof_int32) strlen(pfp->filename) : 0;
		pack_int32(slen, &bp, &remain);
		if (slen) {
		    memcpy(bp, pfp->filename, (size_t) slen);
		    bp += slen;
		    remain -= (size_t) slen;
		}
	    }
	    pack_int32(PROF_MAGIC_PROFILE, &bp, &remain);
	    retval = 0;
	    *bufpp = bp;
	    *remainp = remain;
	}
    }
    return(retval);
}

static int unpack_int32(intp, bufpp, remainp)
    prof_int32		*intp;
    unsigned char	**bufpp;
    size_t		*remainp;
{
    if (*remainp >= sizeof(prof_int32)) {
	*intp = (((prof_int32) (*bufpp)[0] << 24) |
		 ((prof_int32) (*bufpp)[1] << 16) |
		 ((prof_int32) (*bufpp)[2] << 8) |
		 ((prof_int32) (*bufpp)[3]));
	*bufpp += sizeof(prof_int32);
	*remainp -= sizeof(prof_int32);
	return 0;
    }
    else
	return 1;
}

errcode_t profile_ser_internalize(unused, profilep, bufpp, remainp)
    const char		*unused;
    profile_t		*profilep;
    unsigned char	**bufpp;
    size_t		*remainp;
{
    errcode_t		retval;
    unsigned char	*bp;
    size_t		remain;
    int			i;
    prof_int32		fcount, tmp;
    char		**flist;

    bp = *bufpp;
    remain = *remainp;
    retval = EINVAL;

    if (remain >= 12)
	(void) unpack_int32(&tmp, &bp, &remain);
    else
	tmp = 0;
    if (tmp == PROF_MAGIC_PROFILE) {
	(void) unpack_int32(&fcount, &bp, &remain);
	retval = ENOMEM;
	if (!fcount ||
	    (flist = (char **) malloc(sizeof(char *) * (fcount + 1)))) {
	    memset(flist, 0, sizeof(char *) * (fcount+1));
	    for (i=0; i<fcount; i++) {
		if (!unpack_int32(&tmp, &bp, &remain)) {
		    if ((flist[i] = (char *) malloc((size_t) (tmp+1)))) {
			memcpy(flist[i], bp, (size_t) tmp);
			flist[i][tmp] = '\0';
			bp += tmp;
			remain -= (size_t) tmp;
		    }
		    else
			break;
		}
		else
		    break;
	    }
	    if ((i == fcount) &&
		!unpack_int32(&tmp, &bp, &remain) &&
		(tmp == PROF_MAGIC_PROFILE))
		retval = profile_init((const char **)flist, profilep);

	    if (!retval) {
		*bufpp = bp;
		*remainp = remain;
	    }

	    for (i=0; i<fcount; i++) {
		if (flist[i])
		    free(flist[i]);
	    }
	    free(flist);
	}
    }
    return(retval);
}

