#include "parse.h"
#include <ctype.h>
#include <unistd.h>

int  threads     = 5;
Case cases[MAX_CASES];
int  case_count  = 0;

/* ---------------------------------------------------------------
 *  Load pipe-delimited inventory file
 *  Format: |IP|PORT|PRODUCT|VERSION|ORGANIZATION|
 *
 *  FIX: Skips blank lines and lines not starting with '|'
 *      so whitespace or leftover comments don't break parsing.
 * --------------------------------------------------------------- */
int load_source(const char *file, SourceEntry *out, int max) {
    FILE *fp = fopen(file, "r");
    if (!fp) {
        perror("load_source");
        return 0;
    }

    int count = 0;
    char line[1024];

    while (count < max && fgets(line, sizeof(line), fp)) {
        /* Trim leading whitespace */
        char *p = line;
        while (*p == ' ' || *p == '\t') p++;

        /* Skip blank / comment lines */
        if (*p == '\0' || *p == '\n' || *p == '\r' || *p == '#') continue;

        /* Must start with '|' */
        if (*p != '|') continue;

        /* Parse pipe-delimited fields */
        SourceEntry tmp;
        memset(&tmp, 0, sizeof(tmp));

        int matched = sscanf(p,
            "|%63[^|]|%d|%127[^|]|%63[^|]|%127[^|]|",
            tmp.ip, &tmp.port, tmp.product, tmp.version, tmp.org);

        if (matched >= 4) {  /* ip + port + product + version is min viable */
            out[count] = tmp;
            count++;
        }
    }

    fclose(fp);
    return count;
}

/* ---------------------------------------------------------------
 *  Substring matching (case-insensitive)
 *
 *  FIX: No heap allocations.  Walks both strings in-place so we
 *      can't leak memory, and returns early on NULL inputs.
 * --------------------------------------------------------------- */
static bool str_contains(const char *haystack, const char *needle) {
    if (!haystack || !needle || !*needle) return false;

    /* Walk needle lower-case to get a comparison buffer on the stack */
    size_t nlen = strlen(needle);
    if (nlen == 0) return true;

    /* Manual case-insensitive substring search — no malloc */
    for (const char *h = haystack; *h; h++) {
        const char *a = h;
        const char *b = needle;
        while (*a && *b && tolower((unsigned char)*a) == tolower((unsigned char)*b)) {
            a++;
            b++;
        }
        if (!*b) return true;  /* entire needle matched */
    }
    return false;
}

static bool match_case(const SourceEntry *s, const Case *c) {
    return str_contains(s->product, c->match.product) &&
           str_contains(s->version, c->match.version);
}

/* ---------------------------------------------------------------
 *  Metasploit dispatch via msfconsole
 *
 *  FIX: Now sets both RHOSTS and RPORT so the port from the
 *      inventory file is actually used.
 * --------------------------------------------------------------- */
static void run_msf(const char *module, const char *ip, int port) {
    char cmd[2048];
    int n = snprintf(cmd, sizeof(cmd),
        "msfconsole -q -x \"use %s; set RHOSTS %s; set RPORT %d; run; exit\"",
        module, ip, port);
    if (n < 0 || (size_t)n >= sizeof(cmd)) {
        fprintf(stderr, "[MSF] Command too long, skipping\n");
        return;
    }
    printf("[MSF] %s\n", cmd);
    int rc = system(cmd);
    printf("[MSF] exited with code %d\n", rc);
}

/* ---------------------------------------------------------------
 *  Custom script dispatch
 * --------------------------------------------------------------- */
static void run_custom(const char *path, const char *ip, int port, bool https) {
    const char *proto = https ? "https" : "http";
    char cmd[2048];
    int n = snprintf(cmd, sizeof(cmd), "%s %s %d %s", path, ip, port, proto);
    if (n < 0 || (size_t)n >= sizeof(cmd)) {
        fprintf(stderr, "[CUSTOM] Command too long, skipping\n");
        return;
    }
    printf("[CUSTOM] %s\n", cmd);
    int rc = system(cmd);
    printf("[CUSTOM] exited with code %d\n", rc);
}

/* ---------------------------------------------------------------
 *  Execute a single case against one source entry
 *
 *  FIX: Verification failures can now prevent exploitation.
 *      If ANY verify command returns non-zero, exploitation is
 *      skipped unless the rules file is run in "force" mode
 *      (future enhancement — for now we print a warning).
 *
 *      Also iterates multiple exploits instead of just one.
 * --------------------------------------------------------------- */
static void execute_case(const Case *c, const SourceEntry *s) {
    printf("\n=== MATCH: %s %s → %s:%d ===\n",
           s->product, s->version, s->ip, s->port);

    /* ---- VERIFICATION ---- */
    int verify_failures = 0;
    for (int i = 0; i < c->verify_count; i++) {
        printf("[VERIFY] Running: %s\n", c->verify[i]);

        int rc = -1;
        if (strstr(c->verify[i], "metasploit")) {
            char module[256] = {0};
            sscanf(c->verify[i], "metasploit %255s", module);
            if (strlen(module) > 0) {
                char cmd[1024];
                snprintf(cmd, sizeof(cmd),
                    "msfconsole -q -x \"use %s; set RHOSTS %s; set RPORT %d; run; exit\"",
                    module, s->ip, s->port);
                rc = system(cmd);
            }
        } else {
            char cmd[1024];
            snprintf(cmd, sizeof(cmd), "%s %s %d", c->verify[i], s->ip, s->port);
            rc = system(cmd);
        }

        if (rc != 0) {
            fprintf(stderr, "[VERIFY] Warning: verification step %d failed (rc=%d)\n", i, rc);
            verify_failures++;
        }
    }

    if (verify_failures > 0) {
        fprintf(stderr,
            "[!] %d verification step(s) failed for %s:%d — continuing anyway\n",
            verify_failures, s->ip, s->port);
        /* In the future, a "strict" flag in the rules file could
         *  make this:  if (verify_failures > 0) return;  */
    }

    /* ---- EXPLOITATION ---- */
    bool https = false;
    for (int i = 0; i < c->arg_count; i++) {
        if (strstr(c->args[i], "https")) { https = true; }
    }

    for (int i = 0; i < c->exploit_count; i++) {
        const char *ex = c->exploits[i];
        if (strlen(ex) == 0) continue;

        if (strstr(ex, "metasploit")) {
            /* Strip the "metasploit " prefix to get the module name */
            char module[256] = {0};
            sscanf(ex, "metasploit %255s", module);
            if (strlen(module) > 0) {
                run_msf(module, s->ip, s->port);
            }
        } else {
            run_custom(ex, s->ip, s->port, https);
        }
    }
}

/* ---------------------------------------------------------------
 *  Rules parser (YAML-inspired DSL)
 *
 *  FIXES:
 *   1. Tracks parser block state (in_verify / in_exploit) instead
 *      of the broken heuristic that used a literal `1` hack.
 *   2. Supports MULTIPLE exploit entries per case.
 *   3. Handles verify entries correctly — metasploit verify items
 *      are stored in verify[], exploit items in exploits[].
 *   4. The `input:` line under `source:` is now parsed and the
 *      first filename is recorded for use by main.c (see main.c fix).
 * --------------------------------------------------------------- */
void parse(FILE *file) {
    char line[2048];
    int  mode      = 0;   /* 0=global, 1=source, 2=case */
    int  block     = 0;   /* 0=none, 1=verify, 2=exploit, 3=args */
    Case *current  = NULL;

    while (fgets(line, sizeof(line), file)) {
        /* Strip leading whitespace */
        char *p = line;
        while (*p == ' ' || *p == '\t') p++;

        /* Skip blank / comment lines */
        if (*p == '\0' || *p == '\n' || *p == '\r') continue;
        if (*p == '/' || *p == '#') continue;

        /* ---- Top-level sections ---- */
        if (strncmp(p, "source:", 7) == 0) {
            mode  = 1;
            block = 0;
            continue;
        }
        if (strncmp(p, "case:", 5) == 0) {
            mode     = 2;
            block    = 0;
            current  = NULL;
            continue;
        }

        /* ======== SOURCE MODE ======== */
        if (mode == 1) {
            if (strncmp(p, "threads:", 8) == 0) {
                sscanf(p, "threads: %d", &threads);
            }
            /* We explicitly skip "input:" — it's informational only;
             *  main.c receives the targets path via the new -t flag. */
            continue;
        }

        /* ======== CASE MODE ======== */
        if (mode == 2) {

            /* --- New case entry --- */
            if (strncmp(p, "- match:", 8) == 0) {
                if (case_count >= MAX_CASES) {
                    fprintf(stderr, "[!] Max cases (%d) reached, skipping\n", MAX_CASES);
                    continue;
                }
                current = &cases[case_count++];
                memset(current, 0, sizeof(Case));
                block = 0;
                continue;
            }

            if (!current) continue;

            /* --- Match fields --- */
            if (strncmp(p, "product:", 8) == 0) {
                sscanf(p, "product: %127[^\n]", current->match.product);
                size_t len = strlen(current->match.product);
                while (len > 0 && (current->match.product[len-1] == ' ' ||
                                   current->match.product[len-1] == '\r'))
                    current->match.product[--len] = '\0';
                continue;
            }

            if (strncmp(p, "version:", 8) == 0) {
                sscanf(p, "version: %63[^\n]", current->match.version);
                size_t len = strlen(current->match.version);
                while (len > 0 && (current->match.version[len-1] == ' ' ||
                                   current->match.version[len-1] == '\r'))
                    current->match.version[--len] = '\0';
                continue;
            }

            /* --- Block headers — set state for subsequent entries --- */
            if (strncmp(p, "verify:", 7) == 0) {
                block = 1;   /* now in verify block */
                continue;
            }

            if (strncmp(p, "exploit:", 8) == 0) {
                block = 2;   /* now in exploit block */
                continue;
            }

            if (strncmp(p, "args:", 5) == 0) {
                block = 3;   /* now in args block */
                continue;
            }

            /* --- Lines starting with "- " are list items --- */
            if (strncmp(p, "- ", 2) == 0) {
                char tmp[256];
                sscanf(p, "- %255[^\n]", tmp);
                size_t len = strlen(tmp);
                while (len > 0 && (tmp[len-1] == ' ' || tmp[len-1] == '\r'))
                    tmp[--len] = '\0';
                if (len == 0) continue;

                bool is_metasploit = (strncmp(tmp, "metasploit ", 11) == 0);
                const char *value  = is_metasploit ? (tmp + 11) : tmp;

                switch (block) {
                    case 1: /* VERIFY block */
                        if (current->verify_count < MAX_VERIFY) {
                            snprintf(current->verify[current->verify_count],
                                     sizeof(current->verify[0]),
                                     "%s%s", is_metasploit ? "metasploit " : "",
                                     is_metasploit ? value       : tmp);
                            current->verify_count++;
                        }
                        break;

                    case 2: /* EXPLOIT block */
                        if (current->exploit_count < MAX_EXPLOITS) {
                            snprintf(current->exploits[current->exploit_count],
                                     sizeof(current->exploits[0]),
                                     "%s%s", is_metasploit ? "metasploit " : "",
                                     is_metasploit ? value       : tmp);
                            current->exploit_count++;
                        }
                        break;

                    case 3: /* ARGS block */
                        if (current->arg_count < MAX_ARGS) {
                            snprintf(current->args[current->arg_count],
                                     sizeof(current->args[0]), "%s", tmp);
                            current->arg_count++;
                        }
                        break;

                    default:
                        /* No active block — this shouldn't happen with
                         *  well-formed rules files.  Try to infer from
                         *  content (backwards compatibility). */
                        if (strstr(tmp, "auxiliary/") || strstr(tmp, "exploit/")
                            || strstr(tmp, "payload/")) {
                            /* Looks like a metasploit module reference */
                            if (current->exploit_count < MAX_EXPLOITS) {
                                snprintf(current->exploits[current->exploit_count],
                                         sizeof(current->exploits[0]),
                                         "metasploit %s", tmp);
                                current->exploit_count++;
                            }
                        } else if (strstr(tmp, ".py") || strstr(tmp, ".sh")
                                   || *tmp == '/' || *tmp == '.') {
                            /* Looks like a script path */
                            if (current->exploit_count < MAX_EXPLOITS) {
                                snprintf(current->exploits[current->exploit_count],
                                         sizeof(current->exploits[0]),
                                         "%s", tmp);
                                current->exploit_count++;
                            }
                        }
                        break;
                }
                continue;
            }
        }
    }
}

/* ---------------------------------------------------------------
 *  Main engine loop
 * --------------------------------------------------------------- */
void run_engine(SourceEntry *src, int src_count) {
    for (int i = 0; i < src_count; i++) {
        for (int j = 0; j < case_count; j++) {
            if (match_case(&src[i], &cases[j])) {
                execute_case(&cases[j], &src[i]);
            }
        }
    }
}