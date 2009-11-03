/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */

extern int optind;
extern char *optarg;

main(argc, argv)
int argc;
char **argv;
{
    int c;
    int errflg = 0;

    <<<other globals here>>>;

    while ((c = getopt(argc, argv, "<<<>>>")) != -1) {
        switch (c) {
            <<<add cases for arguments here>>>;
        case '?':
        default:
            errflg++;
            break;
        }
    }
    if (errflg) {
        fprintf(stderr, "Usage: %s <<<args>>>", argv[0]);
        exit(2);
    }
    for (; optind < argc; optind++) {
        <<<process arg optind>>>;
    }
}
