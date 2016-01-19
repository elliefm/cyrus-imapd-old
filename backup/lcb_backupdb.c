/* lcb_backupdb.c -- replication-based backup api database functions
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
 *
 */

#include <config.h>

#include <sys/types.h>

#include <dirent.h>
#include <errno.h>
#include <syslog.h>

#include "lib/cyrusdb.h"
#include "lib/libconfig.h"
#include "lib/util.h"

#include "imap/global.h"

#include "backup/backup.h"

#define LIBCYRUS_BACKUP_SOURCE /* this file is part of libcyrus_backup */
#include "backup/lcb_internal.h"

EXPORTED int backupdb_open(struct db **backup_dbp, struct txn **tidp)
{
    char *fname = xstrdup(config_getstring(IMAPOPT_BACKUP_DB_PATH));

    if (!fname)
        fname = strconcat(config_dir, FNAME_BACKUPDB, NULL);

    int r = cyrusdb_lockopen(config_backup_db, fname, 0, backup_dbp, tidp);

    free(fname);
    return r;
}

static int is_timestamped(const char *fname)
{
    const char *p = strrchr(fname, '.');

    if (!p) return 0;

    p++; /* eat the dot */
    while (*p) {
        if (!cyrus_isdigit(*p))
            return 0;
        p++;
    }

    return 1;
}

static int is_index(const char *fname)
{
    const char *p = strrchr(fname, '.');

    if (!p) return 0;

    return !strcmp(p, ".index");
}

static int is_old(const char *fname)
{
    const char *p = strrchr(fname, '.');

    if (!p) return 0;

    return !strcmp(p, ".old");
}

static int reconstruct_partition(partitem_t *part_item, void *rock)
{
    const char *partition_root = part_item->value;
    DIR *root_dir = NULL, *hash_dir = NULL;
    struct dirent *root_dirent = NULL, *hash_dirent = NULL;
    char *hash_root;
    int r;

    (void) rock;

    root_dir = opendir(partition_root);
    if (!root_dir) {
        syslog(LOG_ERR, "IOERROR: opendir %s: %m", partition_root);
        return -1; // FIXME error values
    }

    errno = 0;
    while ((root_dirent = readdir(root_dir)) != NULL) {
        if (root_dirent->d_name[0] == '.') continue;

        hash_root = strconcat(partition_root, "/", root_dirent->d_name, NULL);

        if ((hash_dir = opendir(hash_root)) != NULL) {
            while ((hash_dirent = readdir(hash_dir)) != NULL) {
                struct stat sbuf;
                char fname[PATH_MAX];
                int n;

                /* skip current dir, parent dir and hidden files */
                if (hash_dirent->d_name[0] == '.') continue;

                /* skip timestamped old files */
                if (is_timestamped(hash_dirent->d_name)) continue;

                /* skip .old files */
                if (is_old(hash_dirent->d_name)) continue;

                /* skip index files */
                if (is_index(hash_dirent->d_name)) continue;

                /* skip unreadable files */
                n = snprintf(fname, sizeof(fname), "%s/%s",
                             hash_root, hash_dirent->d_name);
                if (n <= 0 || (unsigned) n >= sizeof(fname)) continue;
                if (stat(fname, &sbuf) != 0) continue;

                /* skip empty files */
                if (sbuf.st_size == 0) continue;

                /* skip directories and such */
                if (!S_ISREG(sbuf.st_mode)) continue;

                fprintf(stderr, "%s\n", fname);
            }

            closedir(hash_dir);
        }

        free(hash_root);
    }
    if (errno) {
        syslog(LOG_ERR, "IOERROR: readdir %s: %m", partition_root);
        r = -1; // FIXME error values
    }

    closedir(root_dir);
    return r;
}

EXPORTED int backupdb_reconstruct(void)
{
    return partlist_backup_foreach(reconstruct_partition, NULL);
}
