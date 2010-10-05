/* various methods to collect entropy */
#include "prng.h"

#include "fortuna.h"
#include "k5-int.h"

#ifndef min
#define min(a, b)       ((a) < (b) ? (a) : (b))
#endif

krb5_error_code
k5_entropy_from_device(krb5_context context, const char *device, unsigned char* buf, int buflen)
{
    struct stat sb;
    int fd;
    unsigned char *bp;
    size_t left;
    fd = open(device, O_RDONLY);
    if (fd == -1)
        return 0;
    set_cloexec_fd(fd);
    if (fstat(fd, &sb) == -1 || S_ISREG(sb.st_mode)) {
        close(fd);
        return 0;
    }

    for (bp = buf, left = sizeof(buf); left > 0;) {
        ssize_t count;
        count = read(fd, bp, (unsigned) left);
        if (count <= 0) {
            close(fd);
            return 0;
        }
        left -= count;
        bp += count;
    }
    close(fd);
    return 0;
}

krb5_error_code
k5_entropy_dev_random(krb5_context context, unsigned char* buf, int buflen)
{
    memset(buf, 0, buflen);
    return k5_entropy_from_device(context,"/dev/random", buf, buflen);
}

krb5_error_code
k5_entropy_dev_urandom(krb5_context context, unsigned char* buf, int buflen)
{
    memset(buf, 0, buflen);
    return k5_entropy_from_device(context,"/dev/urandom", buf, buflen);
}

krb5_error_code
k5_entropy_pid(krb5_context context, unsigned char* buf, int buflen)
{
    pid_t pid = getpid(); 
    int pidlen = min(buflen,(int)sizeof(&pid));
    memset(buf, 0, buflen);
    memcpy(buf, &pid, pidlen);
    return 0;
}

krb5_error_code
k5_entropy_uid(krb5_context context, unsigned char* buf, int buflen)
{
    pid_t uid = getuid(); 
    int uidlen=min(buflen,(int)sizeof(&uid));
    memset(buf, 0, buflen);
    memcpy(buf, &uid, uidlen);
    return 0;
}

#ifdef TEST_FORTUNA
int
test_entr(krb5_context context, unsigned char* buf, int buflen)
{
    char buf1[26] = "Seed To Test Fortuna PRNG";
    memset(buf, 0, buflen);
    memcpy(buf, buf1, min(buflen, 26));
    return 0;
}
#endif
