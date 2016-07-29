/* rebuild.c -- wrapper functions for rebuilding sieve bytecode
 *
 * Copyright (c) 1994-2016 Carnegie Mellon University.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. The name "Carnegie Mellon University" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For permission or any legal
 *    details, please contact
 *      Carnegie Mellon University
 *      Center for Technology Transfer and Enterprise Creation
 *      4615 Forbes Avenue
 *      Suite 302
 *      Pittsburgh, PA  15213
 *      (412) 268-7393, fax: (412) 268-7395
 *      innovation@andrew.cmu.edu
 *
 * 4. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by Computing Services
 *     at Carnegie Mellon University (http://www.cmu.edu/computing/)."
 *
 * CARNEGIE MELLON UNIVERSITY DISCLAIMS ALL WARRANTIES WITH REGARD TO
 * THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS, IN NO EVENT SHALL CARNEGIE MELLON UNIVERSITY BE LIABLE
 * FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
 * AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <config.h>

#include <string.h>
#include <syslog.h>

#include "lib/util.h"
#include "lib/xmalloc.h"
#include "lib/xstrlcat.h"
#include "lib/xstrlcpy.h"

#include "imap/imap_err.h"
#include "imap/mailbox.h"

#include "sieve/sieve_interface.h"

EXPORTED char *sieve_getbcfname(const char *script_fname)
{
    char tmp[MAX_MAILBOX_PATH + 1];
    char *ext;
    size_t len;

    len = strlcpy(tmp, script_fname, sizeof(tmp));
    if (len >= sizeof(tmp))
        return NULL;

    ext = strrchr(tmp, '.');
    if (!ext || strcmp(ext, ".script"))
        return NULL;

    *ext = '\0';
    len = strlcat(tmp, ".bc", sizeof(tmp));
    if (len >= sizeof(tmp))
        return NULL;

    return xstrdup(tmp);
}

EXPORTED char *sieve_getscriptfname(const char *bc_name)
{
    char tmp[MAX_MAILBOX_PATH + 1];
    char *ext;
    size_t len;

    len = strlcpy(tmp, bc_name, sizeof(tmp));
    if (len >= sizeof(tmp))
        return NULL;

    ext = strrchr(tmp, '.');
    if (!ext || strcmp(ext, ".bc"))
        return NULL;

    *ext = '\0';
    len = strlcat(tmp, ".script", sizeof(tmp));
    if (len >= sizeof(tmp))
        return NULL;

    return xstrdup(tmp);
}

EXPORTED int sieve_rebuild(const char *script_fname, const char *bc_fname,
                           int force, char **out_parse_errors)
{
    char new_bc_fname[MAX_MAILBOX_PATH + 1];
    FILE *script_file = NULL;
    char *parse_errors = NULL;
    sieve_script_t *script = NULL;
    bytecode_info_t *bc = NULL;
    int bc_fd = -1;
    int r;
    size_t len;

    /* exit early if bc is up to date */
    if (!force) {
        struct stat script_stat, bc_stat;

        r = stat(script_fname, &script_stat);
        if (r) {
            syslog(LOG_DEBUG, "%s: stat %s: %m", __func__, script_fname);
            return SIEVE_FAIL;
        }

        r = stat(bc_fname, &bc_stat);
        if (r && errno != ENOENT) {
            syslog(LOG_DEBUG, "%s: stat %s: %m", __func__, bc_fname);
            return SIEVE_FAIL;
        }

        if (!r && bc_stat.st_mtime >= script_stat.st_mtime) {
            syslog(LOG_DEBUG, "%s: %s is up to date\n", __func__, bc_fname);
            return SIEVE_OK;
        }
    }

    script_file = fopen(script_fname, "r");
    if (!script_file) {
        syslog(LOG_ERR, "IOERROR: unable to open %s for reading: %m",
                        script_fname);
        return IMAP_IOERROR;
    }

    len = strlcpy(new_bc_fname, bc_fname, sizeof(new_bc_fname));
    if (len >= sizeof(new_bc_fname)) {
        syslog(LOG_DEBUG, "%s: filename too long: %s", __func__, bc_fname);
        return SIEVE_FAIL;
    }
    len = strlcat(new_bc_fname, ".NEW", sizeof(new_bc_fname));
    if (len >= sizeof(new_bc_fname)) {
        syslog(LOG_DEBUG, "%s: filename too long: %s", __func__, bc_fname);
        return SIEVE_FAIL;
    }

    bc_fd = open(new_bc_fname, O_CREAT|O_EXCL|O_WRONLY,
                               S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH);
    if (bc_fd < 0) {
        syslog(LOG_ERR, "IOERROR: unable to open %s for writing: %m",
                        new_bc_fname);
        fclose(script_file);
        return IMAP_IOERROR;
    }

    /* if an error occurs after this point, we need to unlink new_bc_fname */

    r = sieve_script_parse_only(script_file, &parse_errors, &script);
    if (r != SIEVE_OK) {
        syslog(LOG_DEBUG, "%s: %s parse failed: %s",
                          __func__, script_fname, parse_errors);
        goto done;
    }

    if (sieve_generate_bytecode(&bc, script) == -1) {
        syslog(LOG_DEBUG, "%s: %s bytecode generation failed: %s",
                          __func__, script_fname, "unknown error");
        r = SIEVE_FAIL;
        goto done;
    }

    if (sieve_emit_bytecode(bc_fd, bc) == -1) {
        syslog(LOG_DEBUG, "%s: unable to emit bytecode to %s: %s",
                          __func__, bc_fname, "unknown error");
        r = SIEVE_FAIL;
        goto done;
    }

    if (rename(new_bc_fname, bc_fname) < 0) {
        r = errno;
        syslog(LOG_ERR, "IOERROR: rename %s -> %s: %m",
                        new_bc_fname, bc_fname);
        goto done;
    }

    syslog(LOG_DEBUG, "%s: %s rebuilt from %s",
                      __func__, bc_fname, script_fname);

done:
    if (r) unlink(new_bc_fname);

    if (parse_errors) {
        if (out_parse_errors)
            *out_parse_errors = parse_errors;
        else
            free(parse_errors);
    }

    if (bc) sieve_free_bytecode(&bc);
    if (script) sieve_script_free(&script);
    if (bc_fd >= 0) close(bc_fd);
    if (script_file) fclose(script_file);

    return r;
}
