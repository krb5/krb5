/* Very simple getuid() for systems that don't have one.  */
#ifndef _MWERKS
int
getuid()
{
	return 42;
}
#endif
