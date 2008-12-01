#if defined(_WIN32)
/* Windows doesn't have the concept of a system log, so just
** do nothing here.
*/
void
syslog(int pri, const char *fmt, ...)
{
   return;
}
#endif
