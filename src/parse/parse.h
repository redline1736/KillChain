#ifndef PARSE_H
#define PARSE_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#define MAX_CASES    64
#define MAX_ARGS     16
#define MAX_SOURCE   256
#define MAX_VERIFY   8
#define MAX_EXPLOITS 8   /* support multiple exploit commands per case */

typedef struct {
    char ip[64];
    int  port;
    char product[128];
    char version[64];
    char org[128];
} SourceEntry;

typedef struct {
    char product[128];
    char version[64];
} Match;

typedef struct {
    Match  match;
    char   verify[MAX_VERIFY][256];
    int    verify_count;
    char   exploits[MAX_EXPLOITS][256];
    int    exploit_count;
    char   args[MAX_ARGS][256];
    int    arg_count;
} Case;

extern int      threads;
extern Case     cases[MAX_CASES];
extern int      case_count;

int  load_source(const char *file, SourceEntry *out, int max);
void parse(FILE *file);
void run_engine(SourceEntry *src, int src_count);
void run_shodan(const char *api, const char *query);

#endif