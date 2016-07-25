#ifndef _KRB5_LABEL_H
#define _KRB5_LABEL_H

#ifdef THREEPARAMOPEN
#undef THREEPARAMOPEN
#endif
#ifdef WRITABLEFOPEN
#undef WRITABLEFOPEN
#endif

/* Wrapper functions which help us create files and directories with the right
 * context labels. */
#ifdef USE_SELINUX
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
FILE *k5_labeled_fopen(const char *path, const char *mode);
int k5_labeled_creat(const char *path, mode_t mode);
int k5_labeled_open(const char *path, int flags, ...);
int k5_labeled_mkdir(const char *path, mode_t mode);
int k5_labeled_mknod(const char *path, mode_t mode, dev_t device);
#define THREEPARAMOPEN(x,y,z) k5_labeled_open(x,y,z)
#define WRITABLEFOPEN(x,y) k5_labeled_fopen(x,y)
void *k5_push_fscreatecon_for(const char *pathname);
void k5_pop_fscreatecon(void *previous);
#else
#define THREEPARAMOPEN(x,y,z) open(x,y,z)
#define WRITABLEFOPEN(x,y) fopen(x,y)
#endif /* USE_SELINUX */
#endif /* _KRB5_LABEL_H */
