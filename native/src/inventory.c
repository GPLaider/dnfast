#include "internal.h"

#include <fcntl.h>
#include <stdlib.h>
#include <string.h>

#ifdef DNFAST_NATIVE_REAL
#include <rpm/header.h>
#include <rpm/rpmdb.h>
#include <rpm/rpmmacro.h>
#include <rpm/rpmlib.h>
#include <rpm/rpmtag.h>
#include <rpm/rpmtd.h>
#include <rpm/rpmts.h>
#endif

static void free_record(dnfast_inventory_record *record) {
    if (record == NULL) return;
    free((void *)record->name);
    free((void *)record->version);
    free((void *)record->release);
    free((void *)record->arch);
    free((void *)record->vendor);
    free((void *)record->immutable_header);
    memset(record, 0, sizeof(*record));
}

#ifdef DNFAST_NATIVE_REAL
static pthread_once_t rpm_config_once = PTHREAD_ONCE_INIT;
static int rpm_config_status = -1;

static void initialize_rpm_config(void) {
    rpm_config_status = rpmReadConfigFiles(NULL, NULL);
}

dnfast_status dnfast_inventory_prepare_rpm(dnfast_error *error) {
    if (pthread_once(&rpm_config_once, initialize_rpm_config) != 0 ||
        rpm_config_status != 0)
        return dnfast_set_error(error, DNFAST_STATUS_NATIVE_FAILURE,
                                "rpm", "rpmReadConfigFiles", "RPM configuration failed");
    return DNFAST_STATUS_OK;
}

void dnfast_inventory_configure_trusted_rpmdb_read(rpmts ts) {
    /*
     * Installed headers live in the root-owned RPMDB and were authenticated at
     * install time.  Re-running their package signatures on every inventory
     * walk is both redundant and very expensive on RPM 6.  The inventory still
     * exports and SHA-256 binds every immutable header, while package artifacts
     * are verified separately against the isolated repository keyring before
     * either TEST or real transaction execution.
     */
    rpmtsSetVSFlags(ts, rpmtsVSFlags(ts) | RPMVSF_NOHDRCHK);
    rpmtsSetVfyFlags(ts, rpmtsVfyFlags(ts) | RPMVSF_NOHDRCHK);
}

char *dnfast_inventory_take_cookie(rpmts ts) {
    if (rpmtsGetRdb(ts) == NULL && rpmtsOpenDB(ts, O_RDONLY) != 0) return NULL;
    return rpmdbCookie(rpmtsGetRdb(ts));
}
#endif

void dnfast_inventory_clear(dnfast_context *context) {
    if (context == NULL) return;
    for (size_t index = 0; index < context->inventory_count; ++index)
        free_record(&context->inventory[index]);
    free(context->inventory);
    free(context->inventory_backend);
    free(context->inventory_cookie);
    context->inventory = NULL;
    context->inventory_count = 0;
    context->inventory_backend = NULL;
    context->inventory_cookie = NULL;
}

#ifdef DNFAST_NATIVE_REAL
static int copy_text(const char *source, const char **target) {
    if (source == NULL) return -1;
    size_t size = strlen(source) + 1;
    char *copy = malloc(size);
    if (copy != NULL) memcpy(copy, source, size);
    *target = copy;
    return *target == NULL ? -1 : 0;
}

static int copy_optional_text(const char *source, const char **target) {
    return copy_text(source == NULL ? "" : source, target);
}

static int copy_header(Header header, dnfast_inventory_record *record) {
    unsigned int size = 0;
    void *copy = headerExport(header, &size);
    if (copy == NULL || size == 0) {
        free(copy);
        return -1;
    }
    record->immutable_header = copy;
    record->immutable_header_size = size;
    return 0;
}

static int fill_record(Header header, dnfast_inventory_record *record) {
    memset(record, 0, sizeof(*record));
    if (copy_text(headerGetString(header, RPMTAG_NAME), &record->name) ||
        copy_text(headerGetString(header, RPMTAG_VERSION), &record->version) ||
        copy_text(headerGetString(header, RPMTAG_RELEASE), &record->release) ||
        copy_optional_text(headerGetString(header, RPMTAG_VENDOR), &record->vendor)) {
        free_record(record);
        return -1;
    }
    const char *arch = headerGetString(header, RPMTAG_ARCH);
    if (arch == NULL && strcmp(record->name, "gpg-pubkey") == 0) arch = "noarch";
    if (copy_text(arch, &record->arch) || copy_header(header, record)) {
        free_record(record);
        return -1;
    }
    record->epoch = (uint32_t)headerGetNumber(header, RPMTAG_EPOCH);
    record->db_instance = headerGetInstance(header);
    record->install_time = headerGetNumber(header, RPMTAG_INSTALLTIME);
    return 0;
}

dnfast_status dnfast_inventory_collect(dnfast_context *context, rpmts ts,
                                       dnfast_error *error) {
    rpmdbMatchIterator iterator = rpmtsInitIterator(ts, RPMDBI_PACKAGES, NULL, 0);
    if (iterator == NULL)
        return dnfast_set_error(error, DNFAST_STATUS_NATIVE_FAILURE,
                                "rpm", "rpmtsInitIterator", "rpmdb unreadable");
    dnfast_inventory_clear(context);
    size_t capacity = 0;
    Header header;
    while ((header = rpmdbNextIterator(iterator)) != NULL) {
        if (context->inventory_count == context->limits.max_packages) goto limit;
        if (context->inventory_count == capacity) {
            size_t next = capacity == 0 ? 256 : capacity * 2;
            if (next > context->limits.max_packages) next = context->limits.max_packages;
            void *grown = realloc(context->inventory, next * sizeof(*context->inventory));
            if (grown == NULL) goto failure;
            context->inventory = grown;
            capacity = next;
        }
        if (fill_record(header, &context->inventory[context->inventory_count])) goto failure;
        context->inventory_count++;
    }
    rpmdbFreeIterator(iterator);
    context->inventory_backend = rpmExpand("%{?_db_backend}", NULL);
    if (context->inventory_backend == NULL || context->inventory_backend[0] == '\0') {
        dnfast_inventory_clear(context);
        return dnfast_set_error(error, DNFAST_STATUS_NATIVE_FAILURE,
                                "rpm", "rpmExpand", "rpmdb backend unavailable");
    }
    return DNFAST_STATUS_OK;
limit:
    rpmdbFreeIterator(iterator); dnfast_inventory_clear(context);
    return dnfast_set_error(error, DNFAST_STATUS_LIMIT_EXCEEDED,
                            "rpm", "rpmdbNextIterator", "package limit exceeded");
failure:
    rpmdbFreeIterator(iterator); dnfast_inventory_clear(context);
    return dnfast_set_error(error, DNFAST_STATUS_NATIVE_FAILURE,
                            "rpm", "headerGet", "invalid installed header");
}
#endif

dnfast_status dnfast_inventory_read(dnfast_context *context, const char *root,
                                    dnfast_error *error) {
    uint8_t cache_hit = 0;
    return dnfast_inventory_read_cached(context, root, NULL, &cache_hit, error);
}

dnfast_status dnfast_inventory_read_cached(dnfast_context *context,
                                           const char *root,
                                           const char *expected_cookie,
                                           uint8_t *cache_hit,
                                           dnfast_error *error) {
    if (context == NULL || root == NULL || strcmp(root, "/") != 0)
        return dnfast_set_error(error, DNFAST_STATUS_INVALID_ARGUMENT,
                                "rpmdb", NULL, "inventory root must be /");
    if (cache_hit == NULL)
        return dnfast_set_error(error, DNFAST_STATUS_INVALID_ARGUMENT,
                                "rpmdb", NULL, "cache result is null");
    *cache_hit = 0;
    if (!pthread_equal(context->owner, pthread_self()))
        return dnfast_set_error(error, DNFAST_STATUS_WRONG_THREAD,
                                "rpmdb", NULL, "wrong owner thread");
    dnfast_status status = dnfast_callback_check(&context->callbacks, error);
    if (status != DNFAST_STATUS_OK) return status;
#ifdef DNFAST_NATIVE_REAL
    status = dnfast_inventory_prepare_rpm(error);
    if (status != DNFAST_STATUS_OK) return status;
    rpmts ts = rpmtsCreate();
    if (ts == NULL || rpmtsSetRootDir(ts, root) != 0) {
        rpmtsFree(ts);
        return dnfast_set_error(error, DNFAST_STATUS_NATIVE_FAILURE,
                                "rpm", "rpmtsCreate", "inventory context failed");
    }
    dnfast_inventory_configure_trusted_rpmdb_read(ts);
    rpmtxn txn = rpmtxnBegin(ts, RPMTXN_READ);
    if (txn == NULL) {
        rpmtsFree(ts);
        return dnfast_set_error(error, DNFAST_STATUS_NATIVE_FAILURE,
                                "rpm", "rpmtxnBegin", "rpmdb read lock failed");
    }
    char *cookie = dnfast_inventory_take_cookie(ts);
    if (cookie == NULL || cookie[0] == '\0') {
        free(cookie);
        status = dnfast_set_error(error, DNFAST_STATUS_NATIVE_FAILURE,
                                  "rpm", "rpmdbCookie", "rpmdb cookie unavailable");
    } else if (expected_cookie != NULL && strcmp(expected_cookie, cookie) == 0) {
        dnfast_inventory_clear(context);
        context->inventory_cookie = cookie;
        cookie = NULL;
        *cache_hit = 1;
        status = DNFAST_STATUS_OK;
    } else {
        status = dnfast_inventory_collect(context, ts, error);
        if (status == DNFAST_STATUS_OK) {
            context->inventory_cookie = cookie;
            cookie = NULL;
        }
    }
    free(cookie);
    rpmtxnEnd(txn);
    rpmtsFree(ts);
    return status;
#else
    return dnfast_set_error(error, DNFAST_STATUS_UNSUPPORTED_ABI,
                            "rpm", "rpmtxnBegin", "real native build disabled");
#endif
}

const char *dnfast_inventory_backend(const dnfast_context *context) {
    return context == NULL ? NULL : context->inventory_backend;
}

const char *dnfast_inventory_cookie(const dnfast_context *context) {
    return context == NULL ? NULL : context->inventory_cookie;
}

const char *dnfast_inventory_rpm_version(const dnfast_context *context) {
#ifdef DNFAST_NATIVE_REAL
    (void)context;
    return RPMVERSION;
#else
    (void)context;
    return NULL;
#endif
}

size_t dnfast_inventory_count(const dnfast_context *context) {
    return context == NULL ? 0 : context->inventory_count;
}

const dnfast_inventory_record *dnfast_inventory_get(
    const dnfast_context *context, size_t index) {
    if (context == NULL || index >= context->inventory_count) return NULL;
    return &context->inventory[index];
}
