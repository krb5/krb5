/* Very simple getuid() for systems that don't have one.  */
#ifndef __MWERKS__
int
getuid()
{
	return 42;
}
#endif
