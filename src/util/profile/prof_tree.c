/*
 * prof_tree.c --- these routines maintain the parse tree of the
 * 	config file.
 * 
 * All of the details of how the tree is stored is abstracted away in
 * this file; all of the other profile routines build, access, and
 * modify the tree via the accessor functions found in this file.
 *
 * Each node may represent either a relation or a section header.
 * 
 * A section header must have its value field set to 0, and may a one
 * or more child nodes, pointed to by first_child.
 * 
 * A relation has as its value a pointer to allocated memory
 * containing a string.  Its first_child pointer must be null.
 *
 */


#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <ctype.h>

#include "prof_int.h"

struct profile_node {
	errcode_t	magic;
	char *name;
	char *value;
	int group_level;
	struct profile_node *first_child;
	struct profile_node *parent;
	struct profile_node *next, *prev;
};

#define CHECK_MAGIC(node) \
	  if ((node)->magic != PROF_MAGIC_NODE) \
		  return PROF_MAGIC_NODE;

/*
 * Free a node, and any children
 */
void profile_free_node(node)
	struct profile_node *node;
{
	struct profile_node *child, *next;

	if (node->magic != PROF_MAGIC_NODE)
		return;
	
	if (node->name)
		free(node->name);
	if (node->value)
		free(node->value);
	for (child=node->first_child; child; child = next) {
		next = child->next;
		profile_free_node(child);
	}
	node->magic = 0;
	
	free(node);
}

/*
 * Create a node
 */
errcode_t profile_create_node(name, value, ret_node)
	const char *name, *value;
	struct profile_node **ret_node;
{
	struct profile_node *new;

	new = malloc(sizeof(struct profile_node));
	if (!new)
		return ENOMEM;
	memset(new, 0, sizeof(struct profile_node));
	new->name = malloc(strlen(name)+1);
	if (new->name == 0) {
		profile_free_node(new);
		return ENOMEM;
	}
	strcpy(new->name, name);
	if (value) {
		new->value = malloc(strlen(value)+1);
		if (new->value == 0) {
			profile_free_node(new);
			return ENOMEM;
		}
		strcpy(new->value, value);
	}
	new->magic = PROF_MAGIC_NODE;

	*ret_node = new;
	return 0;
}

/*
 * This function verifies that all of the representation invarients of
 * the profile are true.  If not, we have a programming bug somewhere,
 * probably in this file.
 */
errcode_t profile_verify_node(node)
	struct profile_node *node;
{
	struct profile_node *p, *last;
	
	CHECK_MAGIC(node);

	if (node->value && node->first_child)
		return PROF_SECTION_WITH_VALUE;

	last = 0;
	for (p = node->first_child; p; last = p, p = p->next) {
		if (p->prev != last)
			return PROF_BAD_LINK_LIST;
		if (last && (last->next != p))
			return PROF_BAD_LINK_LIST;
		if (node->group_level != p->group_level+1)
			return PROF_BAD_GROUP_LVL;
		if (p->parent != node)
			return PROF_BAD_PARENT_PTR;
		profile_verify_node(p);
	}
	return 0;
}

/*
 * Add a node to a particular section
 */
errcode_t profile_add_node(section, name, value, ret_node)
	struct profile_node *section;
	const char *name, *value;
	struct profile_node **ret_node;
{
	errcode_t retval;
	struct profile_node *p, *last, *new;
	int	cmp = -1;

	CHECK_MAGIC(section);

	if (section->value)
		return PROF_ADD_NOT_SECTION;

	for (p=section->first_child, last = 0; p; last = p, p = p->next) {
		cmp = strcmp(p->name, name);
		if (cmp >= 0)
			break;
	}
	retval = profile_create_node(name, value, &new);
	if (retval)
		return retval;
	new->group_level = section->group_level+1;
	new->parent = section;
	if (cmp == 0) {
		do {
			last = p;
			p = p->next;
		} while (p && strcmp(p->name, name) == 0);
	}
	new->prev = last;
	if (last)
		last->next = new;
	else
		section->first_child = new;
	if (p)
		new->next = p;
	if (ret_node)
		*ret_node = new;
	return 0;
}

/*
 * Iterate through the section, returning the relations which match
 * the given name.  If name is NULL, then interate through all the
 * relations in the section.  The first time this routine is called,
 * the state pointer must be null.  When this profile_find_node_relatioon()
 * returns, if the state pointer is non-NULL, then this routine should
 * be called again.
 *
 * The returned character string in value points to the stored
 * character string in the parse string.  Before this string value is
 * returned to a calling application (profile_find_node_relatioon is not an
 * exported interface), it should be strdup()'ed.
 */
errcode_t profile_find_node_relation(section, name, state, ret_name, value)
	struct profile_node *section;
	const char *name;
	void **state;
	char **ret_name, **value;
{
	struct profile_node *p;

	CHECK_MAGIC(section);
	p = *state;
	if (p) {
		CHECK_MAGIC(p);
	} else
		p = section->first_child;
	
	while (p) {
		if (((name == 0) || (strcmp(p->name, name) == 0)) &&
		    p->value) {
			*value = p->value;
			if (ret_name)
				*ret_name = p->name;
			break;
		}
		p = p->next;
	}
	if (p == 0) {
		*state = 0;
		return PROF_NO_RELATION;
	}
	/*
	 * OK, we've found one match; now let's try to find another
	 * one.  This way, if we return a non-zero state pointer,
	 * there's guaranteed to be another match that's returned.
	 */
	p = p->next;
	while (p) {
		if (((name == 0) || (strcmp(p->name, name) == 0)) &&
		    p->value)
			break;
		p = p->next;
	}
	*state = p;
	return 0;
}

/*
 * Iterate through the section, returning the subsections which match
 * the given name.  If name is NULL, then interate through all the
 * subsections in the section.  The first time this routine is called,
 * the state pointer must be null.  When this profile_find_node_subsection()
 * returns, if the state pointer is non-NULL, then this routine should
 * be called again.
 */
errcode_t profile_find_node_subsection(section, name, state, ret_name,
				       subsection)
	struct profile_node *section;
	const char *name;
	void **state;
	char **ret_name;
	struct profile_node **subsection;
{
	struct profile_node *p;

	CHECK_MAGIC(section);
	p = *state;
	if (p) {
		CHECK_MAGIC(p);
	} else
		p = section->first_child;
	
	while (p) {
		if (((name == 0) || (strcmp(p->name, name) == 0)) &&
		    (p->value == 0)) {
			*subsection = p;
			if (ret_name)
				*ret_name = p->name;
			break;
		}
		p = p->next;
	}
	if (p == 0) {
		*state = 0;
		return PROF_NO_SECTION;
	}
	/*
	 * OK, we've found one match; now let's try to find another
	 * one.  This way, if we return a non-zero state pointer,
	 * there's guaranteed to be another match that's returned.
	 */
	p = p->next;
	while (p) {
		if (((name == 0) || (strcmp(p->name, name) == 0))
		    && (p->value == 0))
			break;
		p = p->next;
	}
	*state = p;
	return 0;
}

/*
 * This function deletes a relation from a section.  Subsections are
 * not deleted; if those need to be deleted, they must be done so manually.
 */
errcode_t profile_delete_node_relation(section, name)
	struct profile_node *section;
	const char *name;
{
	struct profile_node *p, *next;
	
	for (p = section->first_child; p; p = p->next) {
		if ((strcmp(p->name, name) == 0) && p->value)
			break;
	}
	if (p == 0)
		return PROF_NO_RELATION;
	/*
	 * Now we start deleting the relations... if we find a
	 * subsection with the same name, delete it and keep going.
	 */
	while (p && (strcmp(p->name, name) == 0)) {
		if (p->value == 0) {
			p = p->next;
			continue;
		}
		if (p->prev)
			p->prev->next = p->next;
		else
			section->first_child = p->next;
		next = p->next;
		if (p->next)
			p->next->prev = p;
		profile_free_node(p);
		p = next;
	}
	return 0;
}

/*
 * This function deletes a relation from a section.  Subsections are
 * not deleted; if those need to be deleted, they must be done so manually.
 * And sections need not have a value to be delete, this is to enable
 * deleting sections which are valueless headers for subsections.
 */
errcode_t profile_delete_interior_node_relation(section, name)
	struct profile_node *section;
	const char *name;
{
	struct profile_node *p, *next;
	
	for (p = section->first_child; p; p = p->next) {
		if ((strcmp(p->name, name) == 0))
			break;
	}
	if (p == 0)
		return PROF_NO_RELATION;
	/*
	 * Now we start deleting the relations... if we find a
	 * subsection with the same name, delete it and keep going.
	 */
	while (p && (strcmp(p->name, name) == 0)) {
		if (p->prev)
			p->prev->next = p->next;
		else
			section->first_child = p->next;
		next = p->next;
		if (p->next)
			p->next->prev = p;
		profile_free_node(p);
		p = next;
	}
	return 0;
}

/*
 * This function returns the parent of a particular node.
 */
errcode_t profile_get_node_parent(section, parent)
	struct profile_node *section, **parent;
{
	*parent = section->parent;
	return 0;
}


/*
 * Taking the state from another find function, give the name of the
 * section and move to the next section.  In this case, state can't be null
 */
errcode_t profile_find_node_name(section, state, ret_name)
	struct profile_node *section;
	void **state;
	char **ret_name;
{
	struct profile_node *p;

	CHECK_MAGIC(section);
	p = *state;
	if (p) {
		CHECK_MAGIC(p);
	} else
		p = section->first_child;
	
	if (p == 0) {
		*state = 0;
		return PROF_NO_SECTION;
	}
/* give the name back */
	*ret_name = p->name;
	p = p->next;

	*state = p;
	return 0;
}
