/* simple implementation of swab. */

swab(from,to,nbytes) 
        char *from;
        char *to;
        int nbytes;
{
	char tmp;
        while ( (nbytes-=2) >= 0 ) {
                tmp = from[1];
                to[1] = from[0];
		to[0] = tmp;
                to++; to++;
                from++; from++;
        }
}


