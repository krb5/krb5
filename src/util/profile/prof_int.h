/*
 * prof-int.h
 */

#include <time.h>
#include "prof_err.h"

#if defined(__STDC__) || defined(_MSDOS) || defined(_WIN32)
#define PROTOTYPE(x) x
#else
#define PROTOTYPE(x) ()
#endif

#if defined(_MSDOS)
/* From k5-config.h */
#define SIZEOF_INT      2
#define SIZEOF_SHORT    2
#define SIZEOF_LONG     4
#endif 

#if defined(_WIN32)
#define SIZEOF_INT      4
#define SIZEOF_SHORT    2
#define SIZEOF_LONG     4
#endif

#if defined(_MACINTOSH)
#define NO_SYS_TYPES_H
#define NO_SYS_STAT_H
#endif

typedef long errcode_t;

/*
 * This is the structure which stores the profile information for a
 * particular configuration file.
 */
struct _prf_file_t {
	errcode_t	magic;
	char	*comment;
	char	*filename;
	struct profile_node *root;
	time_t	timestamp;
	int	flags;
	struct _prf_file_t *next;
};

typedef struct _prf_file_t *prf_file_t;

/*
 * This structure defines the high-level, user visible profile_t
 * object, which is used as a handle by users who need to query some
 * configuration file(s)
 */
struct _profile_t {
	errcode_t	magic;
	prf_file_t	first_file;
};

typedef struct _profile_t *profile_t;

/*
 * This structure defines the profile_section_t object, which is
 * returned to the user when a section is searched.
 */
struct _profile_section_t {
	errcode_t	magic;
	int		top_lvl:1, top_lvl_search:1;
	char		*name;
	void		*state;
	struct profile_node	*parent, *sect;
	profile_t	profile;
	prf_file_t	file_ptr;
};

typedef struct _profile_section_t *profile_section_t;

extern errcode_t profile_get
	PROTOTYPE((const char *filename, prf_file_t *ret_prof));

extern errcode_t profile_update
	PROTOTYPE((prf_file_t profile));

extern errcode_t profile_parse_file
	PROTOTYPE((FILE *f, struct profile_node **root));

/* prof_tree.c */

extern void profile_free_node
	PROTOTYPE((struct profile_node *relation));

extern errcode_t profile_create_node
	PROTOTYPE((const char *name, const char *value,
		   struct profile_node **ret_node));

extern errcode_t profile_verify_node
	PROTOTYPE((struct profile_node *node));

extern errcode_t profile_add_node
	PROTOTYPE ((struct profile_node *section,
		    const char *name, const char *value,
		    struct profile_node **ret_node));

extern errcode_t profile_find_node_relation
	PROTOTYPE ((struct profile_node *section,
		    const char *name, void **state,
		    char **ret_name, char **value));

extern errcode_t profile_find_node_subsection
	PROTOTYPE ((struct profile_node *section,
		    const char *name, void **state,
		    char **ret_name, struct profile_node **subsection));
		   
extern errcode_t profile_get_node_parent
	PROTOTYPE ((struct profile_node *section,
		   struct profile_node **parent));
		   
extern errcode_t profile_delete_node_relation
	PROTOTYPE ((struct profile_node *section, const char *name));

extern errcode_t profile_find_node_name
	PROTOTYPE ((struct profile_node *section, void **state,
		    char **ret_name));

/* prof_file.c */

extern errcode_t profile_open_file
	PROTOTYPE ((const char *filename, prf_file_t *ret_prof));

extern errcode_t profile_update_file
	PROTOTYPE ((prf_file_t profile));

extern errcode_t profile_close_file
	PROTOTYPE ((prf_file_t profile));

/* prof_init.c */

errcode_t profile_init
	PROTOTYPE ((const char **filenames, profile_t *ret_profile));

errcode_t profile_init_path
	PROTOTYPE ((const char *filepath, profile_t *ret_profile));

extern void profile_release
	PROTOTYPE ((profile_t profile));


extern errcode_t profile_get_values
	PROTOTYPE ((profile_t profile, const char **names, char ***ret_values));
extern errcode_t profile_get_string
	PROTOTYPE((profile_t profile, const char *name, const char *subname, 
			const char *subsubname, const char *def_val,
			char **ret_string));
extern errcode_t profile_get_integer
	PROTOTYPE((profile_t profile, const char *name, const char *subname,
			const char *subsubname, int def_val,
			int *ret_default));
