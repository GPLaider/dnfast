#define _POSIX_C_SOURCE 200809L
#include "internal.h"

#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#ifdef DNFAST_NATIVE_REAL
#include <solv/knownid.h>
#include <solv/pool.h>
#include <solv/queue.h>
#include <solv/repo.h>
#include <solv/solvable.h>
#endif

dnfast_status dnfast_limits_before_repo(dnfast_context *context,
                                        const int metadata_fds[3],
                                        size_t metadata_count,
                                        dnfast_error *error) {
    uint64_t total = context->metadata_bytes;
    for (size_t index = 0; index < metadata_count; ++index) {
        struct stat metadata;
        if (fstat(metadata_fds[index], &metadata) != 0 || metadata.st_size < 0)
            return dnfast_set_error(error, DNFAST_STATUS_NATIVE_FAILURE,
                                    "solver", "stat", "metadata stat failed");
        uint64_t size = (uint64_t)metadata.st_size;
        if (UINT64_MAX - total < size ||
            total + size > context->limits.max_metadata_bytes)
            return dnfast_set_error(error, DNFAST_STATUS_LIMIT_EXCEEDED,
                                    "solver", NULL, "metadata byte limit exceeded");
        total += size;
    }
    return DNFAST_STATUS_OK;
}

dnfast_status dnfast_limits_finalize_repo(dnfast_context *context,
                                          struct s_Repo *opaque,
                                          const dnfast_repo_input *input,
                                          FILE *streams[3],
                                          const struct stat identity[3],
                                          size_t metadata_count,
                                          dnfast_error *error) {
#ifdef DNFAST_NATIVE_REAL
    Repo *repo = opaque;
    const char *paths[] = {input->repomd_path, input->primary_path,
                           input->filelists_path};
    int current_fds[3] = {-1, -1, -1};
    uint64_t metadata = 0;
    for (size_t index = 0; index < metadata_count; ++index) {
        struct stat retained;
        struct stat current;
        current_fds[index] = open(paths[index], O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
        int changed = fstat(fileno(streams[index]), &retained) != 0 ||
            current_fds[index] < 0 || fstat(current_fds[index], &current) != 0 ||
            retained.st_dev != identity[index].st_dev ||
            retained.st_ino != identity[index].st_ino ||
            retained.st_size != identity[index].st_size ||
            current.st_dev != identity[index].st_dev ||
            current.st_ino != identity[index].st_ino ||
            current.st_size != identity[index].st_size;
        if (changed || UINT64_MAX - metadata < (uint64_t)identity[index].st_size) {
            for (size_t close_index = 0; close_index < metadata_count; ++close_index)
                if (current_fds[close_index] >= 0) (void)close(current_fds[close_index]);
            return dnfast_set_error(error, changed ? DNFAST_STATUS_NATIVE_FAILURE : DNFAST_STATUS_LIMIT_EXCEEDED,
                                    "solver", changed ? "fstat" : NULL,
                                    changed ? "metadata changed during parse" : "metadata byte count overflow");
        }
        metadata += (uint64_t)identity[index].st_size;
    }
    for (size_t index = 0; index < metadata_count; ++index)
        (void)close(current_fds[index]);
    return dnfast_limits_finalize_loaded_repo(context, repo, metadata, error);
#else
    (void)context;
    (void)opaque;
    (void)input;
    (void)streams;
    (void)identity;
    (void)metadata_count;
    (void)error;
    return DNFAST_STATUS_UNSUPPORTED_ABI;
#endif
}

dnfast_status dnfast_limits_finalize_loaded_repo(dnfast_context *context,
                                                 struct s_Repo *opaque,
                                                 uint64_t metadata_bytes,
                                                 dnfast_error *error) {
#ifdef DNFAST_NATIVE_REAL
    Repo *repo = opaque;
    static const Id keys[] = {SOLVABLE_PROVIDES, SOLVABLE_REQUIRES,
        SOLVABLE_RECOMMENDS, SOLVABLE_SUGGESTS, SOLVABLE_SUPPLEMENTS,
        SOLVABLE_ENHANCES, SOLVABLE_CONFLICTS, SOLVABLE_OBSOLETES};
    Queue values;
    queue_init(&values);
    for (Id id = repo->start; id < repo->end; ++id) {
        uint64_t relations = 0;
        for (size_t key = 0; key < sizeof(keys) / sizeof(keys[0]); ++key) {
            queue_empty(&values);
            solvable_lookup_idarray(pool_id2solvable(context->pool, id), keys[key], &values);
            relations += (uint64_t)values.count;
        }
        if (relations > context->limits.max_relations_per_package) {
            queue_free(&values);
            goto relation_limit;
        }
    }
    queue_free(&values);
    return dnfast_limits_accept_validated_repo(context, repo, metadata_bytes,
                                               error);
relation_limit:
    return dnfast_set_error(error, DNFAST_STATUS_LIMIT_EXCEEDED,
                            "solver", NULL, "relation limit exceeded");
#else
    (void)context;
    (void)opaque;
    (void)metadata_bytes;
    (void)error;
    return DNFAST_STATUS_UNSUPPORTED_ABI;
#endif
}

dnfast_status dnfast_limits_accept_validated_repo(dnfast_context *context,
                                                  struct s_Repo *opaque,
                                                  uint64_t metadata_bytes,
                                                  dnfast_error *error) {
#ifdef DNFAST_NATIVE_REAL
    Repo *repo = opaque;
    if (UINT64_MAX - context->metadata_bytes < metadata_bytes ||
        context->metadata_bytes + metadata_bytes > context->limits.max_metadata_bytes)
        return dnfast_set_error(error, DNFAST_STATUS_LIMIT_EXCEEDED,
                                "solver", NULL, "metadata byte limit exceeded");
    Id package_ids = repo->end - repo->start;
    if (package_ids < 0 || (uint64_t)package_ids > UINT32_MAX)
        return dnfast_set_error(error, DNFAST_STATUS_LIMIT_EXCEEDED,
                                "solver", NULL, "package limit exceeded");
    uint32_t packages = (uint32_t)package_ids;
    if (UINT32_MAX - context->package_count < packages ||
        context->package_count + packages > context->limits.max_packages)
        return dnfast_set_error(error, DNFAST_STATUS_LIMIT_EXCEEDED,
                                "solver", NULL, "package limit exceeded");
    context->package_count += packages;
    context->metadata_bytes += metadata_bytes;
    return DNFAST_STATUS_OK;
#else
    (void)context;
    (void)opaque;
    (void)metadata_bytes;
    (void)error;
    return DNFAST_STATUS_UNSUPPORTED_ABI;
#endif
}

dnfast_status dnfast_limits_accept_extension(dnfast_context *context,
                                             uint64_t metadata_bytes,
                                             dnfast_error *error) {
    if (UINT64_MAX - context->metadata_bytes < metadata_bytes ||
        context->metadata_bytes + metadata_bytes > context->limits.max_metadata_bytes)
        return dnfast_set_error(error, DNFAST_STATUS_LIMIT_EXCEEDED,
                                "solver", NULL, "metadata byte limit exceeded");
    context->metadata_bytes += metadata_bytes;
    return DNFAST_STATUS_OK;
}
