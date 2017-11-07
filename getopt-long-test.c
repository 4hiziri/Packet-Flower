
#include <stdio.h>     /* for printf */
#include <stdlib.h>    /* for exit */
#include <getopt.h>

int
main(int argc, char **argv) {
    int c;
    int digit_optind = 0;

    while (1) {
        int this_option_optind = optind ? optind : 1;
        int option_index = 0;
        static struct option long_options[] = {
	  {"hop-limit",  optional_argument, 0,  0 }, // --hop-limit=123
	  {"fo",         no_argument,       0,  0 }, // make this return macro val
	  {"fm",         no_argument,       0,  0 },
	  {"lifetime",   required_argument, 0,  0 },
	  {"reachable",  required_argument, 0,  0 },
	  {"retrans",    required_argument, 0,  0 },
	  {"r",          required_argument, 0,  0 },
	  {"r-lifetime", required_argument, 0,  0 },
	  {"m",          required_argument, 0,  0 },
	  {"l",          required_argument, 0,  0 },
	  {"p",          required_argument, 0,  0 },
	  {"pl",         no_argument,       0,  0 },
	  {"pa",         no_argument,       0,  0 },
	  {"p-valid",    required_argument, 0,  0 },
	  {"p-prefer",   required_argument, 0,  0 },	  
	  {0,            0,                 0,  0 }
        };

        c = getopt_long_only(argc, argv, "abc:d:012",
                 long_options, &option_index);
        if (c == -1)
            break;

        switch (c) {
        case 0:
            printf("option %s", long_options[option_index].name);
            if (optarg)
                printf(" with arg %s", optarg);
            printf("\n");
            break;

        case '0':
        case '1':
        case '2':
            if (digit_optind != 0 && digit_optind != this_option_optind)
              printf("digits occur in two different argv-elements.\n");
            digit_optind = this_option_optind;
            printf("option %c\n", c);
            break;

        case 'a':
            printf("option a\n");
            break;

        case 'b':
            printf("option b\n");
            break;

        case 'c':
            printf("option c with value '%s'\n", optarg);
            break;

        case 'd':
            printf("option d with value '%s'\n", optarg);
            break;

        case '?':
            break;

        default:
            printf("?? getopt returned character code 0%o ??\n", c);
        }
    }

    if (optind < argc) 
        printf("non-option ARGV-elements: ");
        while (optind < argc)
	  printf("%s ", argv[optind++]);
        printf("\n");
    }

    exit(EXIT_SUCCESS);
}