/*
 * This file is a (rather silly) demonstration of the use of the
 * C Dynamic Object library.  It is a also reasonably thorough test
 * of the library (except that it only tests it with one data size).
 *
 * There are no restrictions on this code; however, if you make any
 * changes, I request that you document them so that I do not get
 * credit or blame for your modifications.
 *
 * Written by Barr3y Jaspan, Student Information Processing Board (SIPB)
 * and MIT-Project Athena, 1989.
 */

#include <stdio.h>
#ifdef USE_DBMALLOC
#include <sys/stdtypes.h>
#include <malloc.h>
#endif

#include "dyn.h"

static char random_string[] = "This is a random string.";
static char insert1[] = "This will be put at the beginning.";
static char insert2[] = "(parenthetical remark!) ";
static char insert3[] = "  This follows the random string.";

main(argc, argv)
   int	argc;
   char	**argv;
{
     DynObject	obj;
     int	i, s;
     char	d, *data;

#ifdef _DEBUG_MALLOC_INC
     union dbmalloptarg arg;
     unsigned long hist1, hist2, o_size, c_size;
#endif

#ifdef _DEBUG_MALLOC_INC
     arg.i = 0;
     dbmallopt(MALLOC_ZERO, &arg);
     dbmallopt(MALLOC_REUSE, &arg);

     o_size = malloc_inuse(&hist1);
#endif 

     obj = DynCreate(sizeof(char), -8);
     if (! obj) {
	  fprintf(stderr, "test: create failed.\n");
	  exit(1);
     }
     
     DynDebug(obj, 1);
     DynParanoid(obj, 1);

     if (DynGet(obj, -5) || DynGet(obj, 0) || DynGet(obj, 1000)) {
	  fprintf(stderr, "test: Get did not fail when it should have.\n");
	  exit(1);
     }

     if (DynDelete(obj, -1) != DYN_BADINDEX ||
	 DynDelete(obj, 0) != DYN_BADINDEX ||
	 DynDelete(obj, 100) != DYN_BADINDEX) {
	  fprintf(stderr, "test: Delete did not fail when it should have.\n");
	  exit(1);
     }

     printf("Size of empty object: %d\n", DynSize(obj));

     for (i=0; i<14; i++) {
	  d = (char) i;
	  if (DynAdd(obj, &d) != DYN_OK) {
	       fprintf(stderr, "test: Adding %d failed.\n", i);
	       exit(1);
	  }
     }

     if (DynAppend(obj, random_string, strlen(random_string)+1) != DYN_OK) {
	  fprintf(stderr, "test: appending array failed.\n");
	  exit(1);
     }
     
     if (DynDelete(obj, DynHigh(obj) / 2) != DYN_OK) {
	  fprintf(stderr, "test: deleting element failed.\n");
	  exit(1);
     }

     if (DynDelete(obj, DynHigh(obj) * 2) == DYN_OK) {
	  fprintf(stderr, "test: delete should have failed here.\n");
	  exit(1);
     }

     d = 200;
     if (DynAdd(obj, &d) != DYN_OK) {
	  fprintf(stderr, "test: Adding %d failed.\n", i);
	  exit(1);
     }

     data = (char *) DynGet(obj, 0);
     s = DynSize(obj);
     for (i=0; i < s; i++)
	  printf("Element %d is %d.\n", i, (unsigned char) data[i]);

     data = (char *) DynGet(obj, 13);
     printf("Element 13 is %d.\n", (unsigned char) *data);

     data = (char *) DynGet(obj, DynSize(obj));
     if (data) {
	  fprintf(stderr, "DynGet did not return NULL when it should have.\n");
	  exit(1);
     }

     printf("This should be the random string: \"%s\"\n", DynGet(obj, 14));

     if (DynInsert(obj, -1, "foo", 4) != DYN_BADINDEX ||
	 DynInsert(obj, DynSize(obj) + 1, "foo", 4) != DYN_BADINDEX ||
	 DynInsert(obj, 0, "foo", -1) != DYN_BADVALUE) {
	  fprintf(stderr, "DynInsert did not fail when it should have.\n");
	  exit(1);
     }

     if (DynInsert(obj, DynSize(obj) - 2, insert3, strlen(insert3) +
		   1) != DYN_OK) {
	  fprintf(stderr, "DynInsert to end failed.\n");
	  exit(1);
     }  

     if (DynInsert(obj, 19, insert2, strlen(insert2)) != DYN_OK) {
	  fprintf(stderr, "DynInsert to middle failed.\n");
	  exit(1);
     }
     
     if (DynInsert(obj, 0, insert1, strlen(insert1)+1) != DYN_OK) {
	  fprintf(stderr, "DynInsert to start failed.\n");
	  exit(1);
     }	

     printf("A new random string: \"%s\"\n", DynGet(obj, 14 +
						    strlen(insert1) + 1));
     printf("This was put at the beginning: \"%s\"\n", DynGet(obj, 0));

     DynDestroy(obj);

#ifdef _DEBUG_MALLOC_INC
     c_size = malloc_inuse(&hist2);
     if (o_size != c_size) {
	  printf("\n\nIgnore a single unfreed malloc segment "
		 "(stdout buffer).\n\n");
	  malloc_list(2, hist1, hist2);
     }
#endif
     

     return 0;
}
