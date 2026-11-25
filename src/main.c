#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libgen.h>   /* for dirname() */

#include "parse/parse.h"

static void print_usage(const char *prog) {
    fprintf(stderr, "Usage: %s <rules_file> [options]\n", prog);
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  -t, --targets <file>   Path to targets file (default: targets.txt)\n");
    fprintf(stderr, "  -h, --help             Show this help\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "Example: %s configs/exploit.rules -t configs/targets.txt\n", prog);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    /* Parse arguments */
    const char *rules_file = argv[1];
    const char *targets_file = "targets.txt";  /* default */

    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "-t") == 0 || strcmp(argv[i], "--targets") == 0) {
            if (i + 1 < argc) {
                targets_file = argv[++i];
            } else {
                fprintf(stderr, "[!] -t/--targets requires a filename argument\n");
                return 1;
            }
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        }
    }

    /* Open and parse the rules file */
    FILE *file = fopen(rules_file, "r");
    if (!file) {
        fprintf(stderr, "[!] Could not open rules file: %s\n", rules_file);
        return 1;
    }

    /* Reset global state so multiple runs work */
    threads    = 5;
    case_count = 0;
    memset(cases, 0, sizeof(cases));

    parse(file);
    fclose(file);

    printf("[*] Loaded %d case(s) with %d thread(s)\n", case_count, threads);

    /* Load sources from targets file */
    SourceEntry sources[MAX_SOURCE];
    int src_count = load_source(targets_file, sources, MAX_SOURCE);
    if (src_count == 0) {
        fprintf(stderr, "[!] No targets loaded (%s missing or empty)\n", targets_file);
        return 1;
    }
    printf("[*] Loaded %d target(s) from %s\n", src_count, targets_file);

    /* Run the engine */
    run_engine(sources, src_count);

    return 0;
}