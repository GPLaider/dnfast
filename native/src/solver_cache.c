#define _POSIX_C_SOURCE 200809L
#include "internal.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define DNFAST_MAX_PACKAGE_LOCATION_BYTES (UINT64_C(1024) * UINT64_C(1024))
#define DNFAST_MAX_RELATION_TEXT_BYTES (UINT64_C(1024) * UINT64_C(1024))
#define DNFAST_MAX_RELATION_SET_BYTES (UINT64_C(16) * UINT64_C(1024) * UINT64_C(1024))

#ifdef DNFAST_NATIVE_REAL
#include <solv/knownid.h>
#include <solv/pool.h>
#include <solv/repo.h>
#include <solv/repo_solv.h>
#include <solv/repo_write.h>
#include <solv/selection.h>
#include <solv/solvable.h>
#include <solv/util.h>
#endif

static dnfast_status owner_check(dnfast_context *context, dnfast_error *error) {
    if (context == NULL)
        return dnfast_set_error(error, DNFAST_STATUS_INVALID_ARGUMENT,
                                "solver-cache", NULL, "context is null");
    if (!pthread_equal(context->owner, pthread_self()))
        return dnfast_set_error(error, DNFAST_STATUS_WRONG_THREAD,
                                "solver-cache", NULL, "wrong owner thread");
    return DNFAST_STATUS_OK;
}

#ifdef DNFAST_NATIVE_REAL
static Repo *find_repo(const dnfast_context *context, const char *repository_id) {
    if (context == NULL || repository_id == NULL) return NULL;
    for (int index = 1; index < context->pool->nrepos; ++index) {
        Repo *repo = context->pool->repos[index];
        if (repo != NULL && repo->name != NULL &&
            strcmp(repo->name, repository_id) == 0)
            return repo;
    }
    return NULL;
}

static Id relation_key(uint8_t kind) {
    switch (kind) {
        case 0: return SOLVABLE_REQUIRES;
        case 1: return SOLVABLE_RECOMMENDS;
        case 2: return SOLVABLE_SUPPLEMENTS;
        case 3: return SOLVABLE_ENHANCES;
        default: return 0;
    }
}

static int relation_stats(Solvable *item, uint8_t kind, size_t *count,
                          size_t *bytes) {
    Queue relations;
    queue_init(&relations);
    solvable_lookup_deparray(item, relation_key(kind), &relations, -1);
    *count = (size_t)relations.count;
    *bytes = 0;
    for (int index = 0; index < relations.count; ++index) {
        const char *text = pool_dep2str(item->repo->pool,
                                       relations.elements[index]);
        size_t length = text == NULL ? 0 : strlen(text) + 1;
        if (length == 0 || length > DNFAST_MAX_RELATION_TEXT_BYTES ||
            SIZE_MAX - *bytes < length ||
            *bytes + length > DNFAST_MAX_RELATION_SET_BYTES) {
            queue_free(&relations);
            return 0;
        }
        *bytes += length;
    }
    queue_free(&relations);
    return 1;
}

static int retained_stream(int retained_fd, const char *mode,
                           FILE **stream, struct stat *identity) {
    if (retained_fd < 0 || fstat(retained_fd, identity) != 0 ||
        !S_ISREG(identity->st_mode) || identity->st_size < 0)
        return 0;
    int duplicate = dup(retained_fd);
    if (duplicate < 0) return 0;
    *stream = fdopen(duplicate, mode);
    if (*stream == NULL) {
        (void)close(duplicate);
        return 0;
    }
    return 1;
}

static const char *package_checksum(Solvable *item, Id *checksum_type) {
    const char *checksum = solvable_lookup_checksum(item, SOLVABLE_CHECKSUM,
                                                    checksum_type);
    if (checksum == NULL)
        checksum = solvable_lookup_checksum(item, SOLVABLE_PKGID,
                                            checksum_type);
    return checksum;
}
#endif

dnfast_status dnfast_solver_add_repo_solv(
    dnfast_context *context, const dnfast_repo_input *input, int retained_fd,
    const uint8_t *expected_userdata, size_t expected_userdata_size,
    dnfast_error *error) {
    dnfast_status status = owner_check(context, error);
    if (status != DNFAST_STATUS_OK) return status;
    if (input == NULL || input->abi_version != DNFAST_NATIVE_ABI_VERSION ||
        input->id == NULL || expected_userdata == NULL ||
        expected_userdata_size == 0 || expected_userdata_size > 4096)
        return dnfast_set_error(error, DNFAST_STATUS_INVALID_ARGUMENT,
                                "solver-cache", NULL, "invalid solv cache input");
    status = dnfast_callback_check(&context->callbacks, error);
    if (status != DNFAST_STATUS_OK) return status;
#ifdef DNFAST_NATIVE_REAL
    FILE *stream = NULL;
    struct stat before;
    if (!retained_stream(retained_fd, "rb", &stream, &before))
        return dnfast_set_error(error, DNFAST_STATUS_NATIVE_FAILURE,
                                "solver-cache", "fdopen", "solv cache open failed");
    if (fseek(stream, 0, SEEK_SET) != 0) {
        (void)fclose(stream);
        return dnfast_set_error(error, DNFAST_STATUS_NATIVE_FAILURE,
                                "solver-cache", "fseek", "solv cache rewind failed");
    }
    int metadata_fds[3] = {fileno(stream), -1, -1};
    status = dnfast_limits_before_repo(context, metadata_fds, 1, error);
    unsigned char *userdata = NULL;
    int userdata_size = 0;
    if (status == DNFAST_STATUS_OK &&
        (solv_read_userdata(stream, &userdata, &userdata_size) != 0 ||
         userdata_size < 0 || (size_t)userdata_size != expected_userdata_size ||
         userdata == NULL ||
         memcmp(userdata, expected_userdata, expected_userdata_size) != 0))
        status = dnfast_set_error(error, DNFAST_STATUS_NATIVE_FAILURE,
                                  "solver-cache", "solv_read_userdata",
                                  "solv cache binding differs");
    solv_free(userdata);
    if (status == DNFAST_STATUS_OK && fseek(stream, 0, SEEK_SET) != 0)
        status = dnfast_set_error(error, DNFAST_STATUS_NATIVE_FAILURE,
                                  "solver-cache", "fseek", "solv cache rewind failed");
    Repo *repo = NULL;
    if (status == DNFAST_STATUS_OK) {
        repo = repo_create(context->pool, input->id);
        if (repo == NULL || repo_add_solv(repo, stream, SOLV_ADD_NO_STUBS) != 0)
            status = dnfast_set_error(error, DNFAST_STATUS_NATIVE_FAILURE,
                                      "libsolv", "repo_add_solv",
                                      "solv cache load failed");
    }
    struct stat after;
    if (status == DNFAST_STATUS_OK &&
        (fstat(fileno(stream), &after) != 0 || before.st_dev != after.st_dev ||
         before.st_ino != after.st_ino || before.st_size != after.st_size))
        status = dnfast_set_error(error, DNFAST_STATUS_NATIVE_FAILURE,
                                  "solver-cache", "fstat",
                                  "solv cache changed during load");
    if (status == DNFAST_STATUS_OK)
        status = dnfast_limits_finalize_loaded_repo(
            context, repo, (uint64_t)before.st_size, error);
    if (fclose(stream) != 0 && status == DNFAST_STATUS_OK)
        status = dnfast_set_error(error, DNFAST_STATUS_NATIVE_FAILURE,
                                  "solver-cache", "fclose",
                                  "solv cache close failed");
    if (status != DNFAST_STATUS_OK) {
        if (repo != NULL) repo_free(repo, 1);
        return status;
    }
    repo->priority = -input->priority;
    repo->subpriority = -input->cost;
    repo_internalize(repo);
    return DNFAST_STATUS_OK;
#else
    (void)input; (void)retained_fd; (void)expected_userdata;
    (void)expected_userdata_size;
    return dnfast_set_error(error, DNFAST_STATUS_UNSUPPORTED_ABI,
                            "solv", "repo_add_solv",
                            "real native build disabled");
#endif
}

dnfast_status dnfast_solver_write_repo_solv(
    dnfast_context *context, const char *repository_id, int retained_fd,
    const uint8_t *userdata, size_t userdata_size, dnfast_error *error) {
    dnfast_status status = owner_check(context, error);
    if (status != DNFAST_STATUS_OK) return status;
    if (repository_id == NULL || userdata == NULL || userdata_size == 0 ||
        userdata_size > 4096 || userdata_size > INT32_MAX)
        return dnfast_set_error(error, DNFAST_STATUS_INVALID_ARGUMENT,
                                "solver-cache", NULL, "invalid solv cache output");
#ifdef DNFAST_NATIVE_REAL
    Repo *repo = find_repo(context, repository_id);
    if (repo == NULL)
        return dnfast_set_error(error, DNFAST_STATUS_INVALID_ARGUMENT,
                                "solver-cache", NULL, "repository was not loaded");
    FILE *stream = NULL;
    struct stat identity;
    if (!retained_stream(retained_fd, "r+b", &stream, &identity) ||
        ftruncate(fileno(stream), 0) != 0 || fseek(stream, 0, SEEK_SET) != 0) {
        if (stream != NULL) (void)fclose(stream);
        return dnfast_set_error(error, DNFAST_STATUS_NATIVE_FAILURE,
                                "solver-cache", "fdopen", "solv cache output failed");
    }
    Repowriter *writer = repowriter_create(repo);
    if (writer == NULL) status = DNFAST_STATUS_NATIVE_FAILURE;
    if (writer != NULL) {
        repowriter_set_userdata(writer, userdata, (int)userdata_size);
        if (repowriter_write(writer, stream) != 0 || fflush(stream) != 0 ||
            fsync(fileno(stream)) != 0)
            status = DNFAST_STATUS_NATIVE_FAILURE;
        repowriter_free(writer);
    }
    if (fclose(stream) != 0) status = DNFAST_STATUS_NATIVE_FAILURE;
    if (status != DNFAST_STATUS_OK)
        return dnfast_set_error(error, DNFAST_STATUS_NATIVE_FAILURE,
                                "libsolv", "repowriter_write",
                                "solv cache write failed");
    return DNFAST_STATUS_OK;
#else
    (void)repository_id; (void)retained_fd; (void)userdata;
    (void)userdata_size;
    return dnfast_set_error(error, DNFAST_STATUS_UNSUPPORTED_ABI,
                            "solv", "repowriter_write",
                            "real native build disabled");
#endif
}

size_t dnfast_solver_repo_package_count(const dnfast_context *context,
                                        const char *repository_id) {
#ifdef DNFAST_NATIVE_REAL
    Repo *repo = find_repo(context, repository_id);
    return repo == NULL ? 0 : (size_t)(repo->end - repo->start);
#else
    (void)context; (void)repository_id;
    return 0;
#endif
}

dnfast_status dnfast_solver_repo_package_get(
    dnfast_context *context, const char *repository_id, size_t ordinal,
    dnfast_repo_package *package, dnfast_error *error) {
    dnfast_status status = owner_check(context, error);
    if (status != DNFAST_STATUS_OK) return status;
    if (package == NULL)
        return dnfast_set_error(error, DNFAST_STATUS_INVALID_ARGUMENT,
                                "solver-cache", NULL, "package output is null");
#ifdef DNFAST_NATIVE_REAL
    Repo *repo = find_repo(context, repository_id);
    if (repo == NULL || ordinal >= (size_t)(repo->end - repo->start))
        return dnfast_set_error(error, DNFAST_STATUS_INVALID_ARGUMENT,
                                "solver-cache", NULL, "package ordinal is invalid");
    Solvable *item = pool_id2solvable(context->pool, repo->start + (Id)ordinal);
    Id checksum_type = 0;
    const char *checksum = package_checksum(item, &checksum_type);
    const char *location = solvable_lookup_location(item, NULL);
    if (item->repo != repo || item->name == 0 || item->arch == 0 || item->evr == 0)
        return dnfast_set_error(error, DNFAST_STATUS_NATIVE_FAILURE,
                                "solver-cache", "package", "package identity is incomplete");
    if (checksum == NULL || checksum_type != REPOKEY_TYPE_SHA256)
        return dnfast_set_error(error, DNFAST_STATUS_NATIVE_FAILURE,
                                "solver-cache", "package", "package checksum is incomplete");
    if (location == NULL)
        return dnfast_set_error(error, DNFAST_STATUS_NATIVE_FAILURE,
                                "solver-cache", "package", "package location is incomplete");
    if (strlen(checksum) != 64 ||
        strlen(location) > DNFAST_MAX_PACKAGE_LOCATION_BYTES)
        return dnfast_set_error(error, DNFAST_STATUS_LIMIT_EXCEEDED,
                                "solver-cache", NULL,
                                "package evidence byte limit exceeded");
    memset(package, 0, sizeof(*package));
    package->name = pool_id2str(context->pool, item->name);
    package->arch = pool_id2str(context->pool, item->arch);
    package->evr = pool_id2str(context->pool, item->evr);
    package->vendor = item->vendor == 0 ? "" :
        pool_id2str(context->pool, item->vendor);
    package->package_size = solvable_lookup_num(item, SOLVABLE_DOWNLOADSIZE, 0);
    package->installed_size = solvable_lookup_num(item, SOLVABLE_INSTALLSIZE, 0);
    package->checksum_size = strlen(checksum);
    package->location_size = strlen(location);
    for (uint8_t kind = 0; kind < 4; ++kind)
        if (!relation_stats(item, kind, &package->relation_counts[kind],
                            &package->relation_bytes[kind]))
            return dnfast_set_error(error, DNFAST_STATUS_NATIVE_FAILURE,
                                    "solver-cache", "pool_dep2str",
                                    "relation evidence is incomplete");
    return DNFAST_STATUS_OK;
#else
    (void)repository_id; (void)ordinal; (void)package;
    return dnfast_set_error(error, DNFAST_STATUS_UNSUPPORTED_ABI,
                            "solv", "repository_package",
                            "real native build disabled");
#endif
}

dnfast_status dnfast_solver_repo_package_payload(
    dnfast_context *context, const char *repository_id, size_t ordinal,
    uint8_t *output, size_t output_size, dnfast_error *error) {
    dnfast_status status = owner_check(context, error);
    if (status != DNFAST_STATUS_OK) return status;
#ifdef DNFAST_NATIVE_REAL
    Repo *repo = find_repo(context, repository_id);
    if (repo == NULL || ordinal >= (size_t)(repo->end - repo->start) ||
        (output_size != 0 && output == NULL))
        return dnfast_set_error(error, DNFAST_STATUS_INVALID_ARGUMENT,
                                "solver-cache", NULL, "package payload request is invalid");
    Solvable *item = pool_id2solvable(context->pool, repo->start + (Id)ordinal);
    Id checksum_type = 0;
    const char *checksum = package_checksum(item, &checksum_type);
    const char *location = solvable_lookup_location(item, NULL);
    size_t checksum_size = checksum == NULL ? 0 : strlen(checksum);
    size_t location_size = location == NULL ? 0 : strlen(location);
    if (checksum_type != REPOKEY_TYPE_SHA256 || checksum_size != 64 ||
        location_size > DNFAST_MAX_PACKAGE_LOCATION_BYTES ||
        location == NULL || SIZE_MAX - checksum_size < location_size ||
        checksum_size + location_size != output_size)
        return dnfast_set_error(error, DNFAST_STATUS_NATIVE_FAILURE,
                                "solver-cache", "package_payload",
                                "package payload changed during extraction");
    memcpy(output, checksum, checksum_size);
    memcpy(output + checksum_size, location, location_size);
    return DNFAST_STATUS_OK;
#else
    (void)repository_id; (void)ordinal; (void)output; (void)output_size;
    return dnfast_set_error(error, DNFAST_STATUS_UNSUPPORTED_ABI,
                            "solv", "repository_package_payload",
                            "real native build disabled");
#endif
}

dnfast_status dnfast_solver_repo_package_relations(
    dnfast_context *context, const char *repository_id, size_t ordinal,
    uint8_t kind, uint8_t *output, size_t output_size,
    dnfast_error *error) {
    dnfast_status status = owner_check(context, error);
    if (status != DNFAST_STATUS_OK) return status;
#ifdef DNFAST_NATIVE_REAL
    Repo *repo = find_repo(context, repository_id);
    if (repo == NULL || ordinal >= (size_t)(repo->end - repo->start) || kind >= 4 ||
        (output_size != 0 && output == NULL))
        return dnfast_set_error(error, DNFAST_STATUS_INVALID_ARGUMENT,
                                "solver-cache", NULL, "relation request is invalid");
    Solvable *item = pool_id2solvable(context->pool, repo->start + (Id)ordinal);
    Queue relations;
    queue_init(&relations);
    solvable_lookup_deparray(item, relation_key(kind), &relations, -1);
    size_t used = 0;
    for (int index = 0; index < relations.count; ++index) {
        const char *text = pool_dep2str(context->pool, relations.elements[index]);
        size_t length = text == NULL ? 0 : strlen(text) + 1;
        if (length == 0 || used > output_size || output_size - used < length) {
            queue_free(&relations);
            return dnfast_set_error(error, DNFAST_STATUS_NATIVE_FAILURE,
                                    "solver-cache", "pool_dep2str",
                                    "relation evidence changed during extraction");
        }
        memcpy(output + used, text, length);
        used += length;
    }
    queue_free(&relations);
    if (used != output_size)
        return dnfast_set_error(error, DNFAST_STATUS_NATIVE_FAILURE,
                                "solver-cache", "relations",
                                "relation size changed during extraction");
    return DNFAST_STATUS_OK;
#else
    (void)repository_id; (void)ordinal; (void)kind; (void)output; (void)output_size;
    return dnfast_set_error(error, DNFAST_STATUS_UNSUPPORTED_ABI,
                            "solv", "repository_relations",
                            "real native build disabled");
#endif
}

uint8_t dnfast_solver_has_provider(const dnfast_context *context,
                                   const char *capability) {
#ifdef DNFAST_NATIVE_REAL
    if (context == NULL || capability == NULL || context->pool->whatprovides == NULL)
        return 0;
    Pool *pool = context->pool;
    Id dependency = pool_str2id(pool, capability, 0);
    if (dependency == 0) return 0;
    Id provider, offset;
    FOR_PROVIDES(provider, offset, dependency) {
        (void)offset;
        Solvable *item = pool_id2solvable(pool, provider);
        if (item->repo != NULL && !item->repo->disabled) return 1;
    }
#else
    (void)context; (void)capability;
#endif
    return 0;
}
