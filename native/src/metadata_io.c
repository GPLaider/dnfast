#define _POSIX_C_SOURCE 200809L
#include "internal.h"

#include <fcntl.h>
#include <unistd.h>

static const char *metadata_path(const dnfast_repo_input *input, size_t index) {
    if (index == 0) return input->repomd_path;
    return index == 1 ? input->primary_path : input->filelists_path;
}

void dnfast_metadata_close(FILE *streams[3]) {
    for (size_t index = 0; index < 3; ++index) {
        if (streams[index] != NULL) {
            (void)fclose(streams[index]);
            streams[index] = NULL;
        }
    }
}

dnfast_status dnfast_metadata_open(const dnfast_repo_input *input,
                                   FILE *streams[3], struct stat identity[3],
                                   size_t stream_count,
                                   dnfast_error *error) {
    if (stream_count < 2 || stream_count > 3)
        return dnfast_set_error(error, DNFAST_STATUS_INVALID_ARGUMENT,
                                "solver", NULL, "invalid metadata stream count");
    for (size_t index = 0; index < stream_count; ++index) {
        int fd = open(metadata_path(input, index), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
        if (fd < 0 || fstat(fd, &identity[index]) != 0 ||
            !S_ISREG(identity[index].st_mode) || identity[index].st_size < 0) {
            if (fd >= 0) (void)close(fd);
            dnfast_metadata_close(streams);
            return dnfast_set_error(error, DNFAST_STATUS_NATIVE_FAILURE,
                                    "solver", "open", "metadata open failed");
        }
        streams[index] = fdopen(fd, "rb");
        if (streams[index] == NULL) {
            (void)close(fd);
            dnfast_metadata_close(streams);
            return dnfast_set_error(error, DNFAST_STATUS_NATIVE_FAILURE,
                                    "solver", "fdopen", "metadata stream failed");
        }
    }
    return DNFAST_STATUS_OK;
}
