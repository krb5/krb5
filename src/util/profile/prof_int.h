/*
 * prof-int.h
 */

#include <time.h>
#include <stdio.h>
#if defined(macintosh) || (defined(__MACH__) && defined(__APPLE__))
#include <TargetConditionals.h>
#define USE_PTHREADS
#define PROFILE_SUPPORTS_FOREIGN_NEWLINES
#define SHARE_TREE_DATA
#endif

#include "com_err.h"
#include "profile.h"

#if defined(_WIN32)
#define SIZEOF_INT      4
#define SIZEOF_SHORT    2
#define SIZEOF_LONG     4
#endif

typedef long prf_magic_t;

/*
 * This is the structure which stores the profile information for a
 * particular configuration file.
 */
struct _prf_data_t {
	prf_magic_t	magic;
	char		*comment;
	profile_filespec_t filespec;
	struct profile_node *root;
	time_t		timestamp; /* time tree was last updated from file */
	int		flags;	/* r/w, dirty */
	int		upd_serial; /* incremented when data changes */
	int		refcount; /* prf_file_t references */
	struct _prf_data_t *next;
};

typedef struct _prf_data_t *prf_data_t;

struct _prf_file_t {
	prf_magic_t	magic;
#ifdef SHARE_TREE_DATA
	struct _prf_data_t	*data;
#else
	struct _prf_data_t	data[1];
#endif
	struct _prf_file_t *next;
};

typedef struct _prf_file_t *prf_file_t;

#ifdef SHARE_TREE_DATA
struct global_shared_profile_data {
	/* This is the head of the global list of shared trees */
	prf_data_t trees;
#ifdef USE_PTHREADS
	/* Lock for above list.  */
	pthread_mutex_t mutex;
#endif
};
extern struct global_shared_profile_data krb5int_profile_shared_data;
#define g_shared_trees		(krb5int_profile_shared_data.trees)

#ifdef USE_PTHREADS
#include <pthread.h>
#define g_shared_trees_mutex	(krb5int_profile_shared_data.mutex)
#define prof_mutex_lock(L)	(pthread_mutex_lock(L))
#define prof_mutex_unlock(L)	(pthread_mutex_unlock(L))
#else
#define prof_mutex_lock(L)	(0)
#define prof_mutex_unlock(L)	(0)
#endif

#endif /* SHARE_TREE_DATA */

/*
 * The profile flags
 */
#define PROFILE_FILE_RW		0x0001
#define PROFILE_FILE_DIRTY	0x0002
#define PROFILE_FILE_SHARED	0x0004

/*
 * This structure defines the high-level, user visible profile_t
 * object, which is used as a handle by users who need to query some
 * configuration file(s)
 */
struct _profile_t {
	prf_magic_t	magic;
	prf_file_t	first_file;
};

/*
 * Used by the profile iterator in prof_get.c
 */
#define PROFILE_ITER_LIST_SECTION	0x0001
#define PROFILE_ITER_SECTIONS_ONLY	0x0002
#define PROFILE_ITER_RELATIONS_ONLY	0x0004

#define PROFILE_ITER_FINAL_SEEN		0x0100

/*
 * Check if a filespec is last in a list (NULL on UNIX, invalid FSSpec on MacOS
 */

#define	PROFILE_LAST_FILESPEC(x) (((x) == NULL) || ((x)[0] == '\0'))

/* profile_parse.c */

errcode_t profile_parse_file
	(FILE *f, struct profile_node **root);

errcode_t profile_write_tree_file
	(struct profile_node *root, FILE *dstfile);


/* prof_tree.c */

void profile_free_node
	(struct profile_node *relation);

errcode_t profile_create_node
	(const char *name, const char *value,
		   struct profile_node **ret_node);

errcode_t profile_verify_node
	(struct profile_node *node);

errcode_t profile_add_node
	(struct profile_node *section,
		    const char *name, const char *value,
		    struct profile_node **ret_node);

errcode_t profile_make_node_final
	(struct profile_node *node);
	
int profile_is_node_final
	(struct profile_node *node);

const char *profile_get_node_name
	(struct profile_node *node);

const char *profile_get_node_value
	(struct profile_node *node);

errcode_t profile_find_node
	(struct profile_node *section,
		    const char *name, const char *value,
		    int section_flag, void **state,
		    struct profile_node **node);

errcode_t profile_find_node_relation
	(struct profile_node *section,
		    const char *name, void **state,
		    char **ret_name, char **value);

errcode_t profile_find_node_subsection
	(struct profile_node *section,
		    const char *name, void **state,
		    char **ret_name, struct profile_node **subsection);
		   
errcode_t profile_get_node_parent
	(struct profile_node *section,
		   struct profile_node **parent);
		   
errcode_t profile_delete_node_relation
	(struct profile_node *section, const char *name);

errcode_t profile_find_node_name
	(struct profile_node *section, void **state,
		    char **ret_name);

errcode_t profile_node_iterator_create
	(profile_t profile, const char *const *names,
		   int flags, void **ret_iter);

void profile_node_iterator_free
	(void	**iter_p);

errcode_t profile_node_iterator
	(void	**iter_p, struct profile_node **ret_node,
		   char **ret_name, char **ret_value);

errcode_t profile_remove_node
	(struct profile_node *node);

errcode_t profile_set_relation_value
	(struct profile_node *node, const char *new_value);

errcode_t profile_rename_node
	(struct profile_node *node, const char *new_name);

/* prof_file.c */

errcode_t profile_open_file
	(const_profile_filespec_t file, prf_file_t *ret_prof);

#define profile_update_file(P) profile_update_file_data((P)->data)
errcode_t profile_update_file_data
	(prf_data_t profile);

#define profile_flush_file(P) (((P) && (P)->magic == PROF_MAGIC_FILE) ? profile_flush_file_data((P)->data) : PROF_MAGIC_FILE)
errcode_t profile_flush_file_data
	(prf_data_t data);

void profile_free_file
	(prf_file_t profile);

errcode_t profile_close_file
	(prf_file_t profile);

void profile_dereference_data (prf_data_t);

/* prof_init.c -- included from profile.h */
errcode_t profile_ser_size
        (const char *, profile_t, size_t *);

errcode_t profile_ser_externalize
        (const char *, profile_t, unsigned char **, size_t *);

errcode_t profile_ser_internalize
        (const char *, profile_t *, unsigned char **, size_t *);

/* prof_get.c */

errcode_t profile_get_value
	(profile_t profile, const char **names,
		    const char	**ret_value);
/* Others included from profile.h */
	
/* prof_set.c -- included from profile.h */
