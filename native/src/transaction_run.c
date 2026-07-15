#include "internal.h"
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifdef DNFAST_NATIVE_REAL
#include <rpm/rpmcallback.h>
#include <rpm/rpmcrypto.h>
#include <rpm/rpmdb.h>
#include <rpm/rpmpgp.h>
#include <rpm/rpmlib.h>
#include <rpm/rpmprob.h>
#include <rpm/rpmps.h>
#include <rpm/rpmtag.h>

static int secure_equal(const uint8_t *left, const uint8_t *right, size_t size) {
    uint8_t different = 0;
    for (size_t index = 0; index < size; ++index) different |= left[index] ^ right[index];
    return different == 0;
}

static int header_digest(Header header, uint8_t output[32]) {
    unsigned int size = 0;
    void *bytes = headerExport(header, &size);
    DIGEST_CTX digest = rpmDigestInit(PGPHASHALGO_SHA256, RPMDIGEST_NONE);
    void *result = NULL;
    size_t result_size = 0;
    int failed = bytes == NULL || size == 0 || digest == NULL ||
        rpmDigestUpdate(digest, bytes, size) != 0 ||
        rpmDigestFinal(digest, &result, &result_size, 0) != 0 || result_size != 32;
    if (!failed) memcpy(output, result, 32);
    free(bytes);
    free(result);
    return failed ? -1 : 0;
}

static int add_erase(rpmts ts, const dnfast_transaction_item *item) {
    uint32_t instance = item->db_instance;
    rpmdbMatchIterator iterator = rpmtsInitIterator(
        ts, RPMDBI_PACKAGES, &instance, sizeof(instance));
    Header header = iterator == NULL ? NULL : rpmdbNextIterator(iterator);
    uint8_t digest[32];
    int valid = header != NULL && rpmdbGetIteratorOffset(iterator) == instance &&
        header_digest(header, digest) == 0 &&
        secure_equal(digest, item->header_sha256, sizeof(digest));
    int result = valid ? rpmtsAddEraseElement(ts, header, 0) : 1;
    if (valid && rpmdbNextIterator(iterator) != NULL) result = 1;
    rpmdbFreeIterator(iterator);
    return result;
}

static int header_matches(Header header, const dnfast_verified_package *expected) {
    char epoch[32];
    snprintf(epoch, sizeof(epoch), "%llu",
             (unsigned long long)headerGetNumber(header, RPMTAG_EPOCHNUM));
    const char *name = headerGetString(header, RPMTAG_NAME);
    const char *version = headerGetString(header, RPMTAG_VERSION);
    const char *release = headerGetString(header, RPMTAG_RELEASE);
    const char *arch = headerGetString(header, RPMTAG_ARCH);
    return name != NULL && version != NULL && release != NULL && arch != NULL &&
        strcmp(name, expected->name) == 0 && strcmp(epoch, expected->epoch) == 0 &&
        strcmp(version, expected->version) == 0 &&
        strcmp(release, expected->release) == 0 && strcmp(arch, expected->arch) == 0;
}

static int add_install(rpmts ts, dnfast_transaction_item *item) {
    struct stat current;
    if (fstat(item->retained_fd, &current) != 0 || current.st_dev != item->device ||
        current.st_ino != item->inode) return 1;
    FD_t fd = fdDup(item->retained_fd);
    Header header = NULL;
    int failed = fd == NULL || Fseek(fd, 0, SEEK_SET) < 0 ||
        rpmReadPackageFile(ts, fd, "<dnfast-retained-fd>", &header) != RPMRC_OK ||
        !header_matches(header, &item->expected.package) ||
        dnfast_verify_payload_digest(item->retained_fd, header) != 0;
    if (!failed)
        failed = rpmtsAddInstallElement(ts, header, item, item->expected.upgrade, NULL) != 0;
    header = headerFree(header);
    if (fd != NULL) Fclose(fd);
    return failed;
}

static void *notify(const void *header, rpmCallbackType what, rpm_loff_t amount,
                    rpm_loff_t total, fnpyKey key, rpmCallbackData data) {
    (void)header; (void)amount; (void)total;
    dnfast_context *context = data;
    dnfast_transaction_item *item = (dnfast_transaction_item *)key;
    if (what == RPMCALLBACK_INST_OPEN_FILE) {
        if (item == NULL || item->active_fd != NULL || item->erase) return NULL;
        context->transaction_counts.open_attempted++;
        if (dnfast_transaction_reverify(context, item) != 0) {
            context->transaction_counts.open_failed++;
            context->transaction_callback_failed = 1; return NULL;
        }
        if (context->transaction_fail_callback == 1) {
            close(item->retained_fd);
            item->retained_fd = -1;
            item->active_fd = fdDup(item->retained_fd);
            context->transaction_counts.open_failed++;
            context->transaction_callback_failed = 1; return NULL;
        }
        struct stat value;
        if (fstat(item->retained_fd, &value) != 0 || value.st_dev != item->device ||
            value.st_ino != item->inode) return NULL;
        item->active_fd = context->transaction_fail_callback == 7
            ? dnfast_transaction_truncated_duplicate(item) : fdDup(item->retained_fd);
        if (context->transaction_fail_callback == 2 && item->active_fd != NULL) {
            close(Fileno(item->active_fd));
        }
        if (item->active_fd == NULL) {
            context->transaction_counts.open_failed++;
            context->transaction_callback_failed = 1; return NULL;
        }
        context->transaction_counts.rewind_attempted++;
        if (Fseek(item->active_fd, 0, SEEK_SET) < 0) {
            if (item->active_fd != NULL) Fclose(item->active_fd);
            item->active_fd = NULL;
            context->transaction_counts.rewind_failed++;
            context->transaction_callback_failed = 1;
            return NULL;
        }
        context->transaction_counts.rewind_succeeded++;
        context->transaction_counts.fd_open++;
        return item->active_fd;
    }
    if (what == RPMCALLBACK_INST_CLOSE_FILE && item != NULL && item->active_fd != NULL) {
        context->transaction_counts.close_attempted++;
        if (context->transaction_fail_callback == 3)
            close(Fileno(item->active_fd));
        int close_result = Fclose(item->active_fd);
        item->active_fd = NULL;
        if (close_result == 0)
            context->transaction_counts.fd_close++;
        else {
            context->transaction_counts.close_failed++;
            context->transaction_callback_failed = 1;
        }
    } else if (what == RPMCALLBACK_SCRIPT_START) context->transaction_counts.script_start++;
    else if (what == RPMCALLBACK_SCRIPT_STOP) context->transaction_counts.script_stop++;
    else if (what == RPMCALLBACK_INST_STOP) context->transaction_counts.package_stop++;
    return NULL;
}

static void clear_problems(dnfast_context *context) {
    for (size_t index = 0; index < context->transaction_problem_count; ++index)
        free(context->transaction_problems[index]);
    free(context->transaction_problems);
    context->transaction_problems = NULL;
    context->transaction_problem_count = 0;
}

static int collect_problems(dnfast_context *context, rpmts ts) {
    clear_problems(context);
    rpmps problems = rpmtsProblems(ts);
    int count = problems == NULL ? 0 : rpmpsNumProblems(problems);
    rpmpsi iterator = count == 0 ? NULL : rpmpsInitIterator(problems);
    for (int index = 0; index < count && rpmpsiNext(iterator) != NULL; ++index) {
        char *text = rpmProblemString(rpmpsGetProblem(iterator));
        void *grown = realloc(context->transaction_problems,
            (context->transaction_problem_count + 1) * sizeof(char *));
        if (text == NULL || grown == NULL) { free(text); count = -1; break; }
        context->transaction_problems = grown;
        context->transaction_problems[context->transaction_problem_count++] = text;
    }
    rpmpsFreeIterator(iterator);
    rpmpsFree(problems);
    if (count > 0 && context->transaction_problem_count == 0 &&
        (context->transaction_problems = calloc(1, sizeof(char *))) != NULL) {
        const char *message = "rpm reported non-iterable transaction problems";
        context->transaction_problems[0] = malloc(strlen(message) + 1);
        if (context->transaction_problems[0] != NULL) { strcpy(context->transaction_problems[0], message); context->transaction_problem_count = 1; }
    }
    return count;
}

static int attempt(dnfast_context *context, int test, int run, int32_t *result) {
    rpmts ts = rpmtsCreate();
    rpmtxn transaction = NULL;
    int stage = 1;
    context->transaction_callback_failed = 0;
    int failed = ts == NULL || rpmtsSetRootDir(ts, "/") != 0 ||
        rpmtsSetKeyring(ts, context->transaction_keyring) != 0;
    if (!failed) {
        stage = 2;
        rpmtsSetVSFlags(ts, RPMVSF_NEEDPAYLOAD);
        rpmtsSetVfyFlags(ts, RPMVSF_NEEDPAYLOAD);
        rpmtsSetVfyLevel(ts, RPMSIG_VERIFIABLE_TYPE);
        rpmtsSetNotifyCallback(ts, notify, context);
        if (test) rpmtsSetFlags(ts, rpmtsFlags(ts) | RPMTRANS_FLAG_TEST);
        transaction = rpmtxnBegin(ts, RPMTXN_WRITE);
        failed = transaction == NULL;
    }
    stage = 3; for (size_t index = 0; !failed && index < context->transaction_item_count; ++index) {
        dnfast_transaction_item *item = context->transaction_items[index];
        failed = item->erase ? add_erase(ts, item) :
            (dnfast_transaction_reverify(context, item) != 0 || add_install(ts, item));
    }
    stage = 4; if (!failed) failed = context->transaction_fail_callback == 4 ||
        rpmtsCheck(ts) != 0 || collect_problems(context, ts) != 0;
    stage = 5; if (!failed) failed = context->transaction_fail_callback == 5 || rpmtsOrder(ts) != 0;
    if (!failed && run) {
        if (!test) {
            if (context->callbacks.transaction_start == NULL ||
                context->callbacks.transaction_start(context->callbacks.user_data) != DNFAST_STATUS_OK)
                failed = 1;
            else context->transaction_phase = DNFAST_TRANSACTION_STARTED;
        }
    }
    if (!failed && run) {
        if (test) context->transaction_counts.test_run++;
        else context->transaction_counts.real_run++;
        *result = rpmtsRun(ts, NULL, RPMPROB_FILTER_NONE);
        int problems_failed = collect_problems(context, ts) != 0;
        if (*result != 0 || problems_failed || context->transaction_callback_failed) failed = 1;
    }
    for (size_t index = 0; index < context->transaction_item_count; ++index) {
        dnfast_transaction_item *item = context->transaction_items[index];
        if (item->active_fd != NULL) { Fclose(item->active_fd); item->active_fd = NULL; }
    }
    if (transaction != NULL) rpmtxnEnd(transaction);
    rpmtsFree(ts);
    if (failed && !run) *result = stage;
    return failed;
}
#endif

static dnfast_status execute(dnfast_context *context, int test, int run,
                             int32_t *result, dnfast_error *error) {
    if (context == NULL || (run && result == NULL))
        return dnfast_set_error(error, DNFAST_STATUS_INVALID_ARGUMENT,
                                "rpm", "transaction", "invalid transaction state");
#ifdef DNFAST_NATIVE_REAL
    if (context->inventory_write_txn == NULL || context->transaction_keyring == NULL ||
        context->transaction_item_count == 0 ||
        context->transaction_phase != DNFAST_TRANSACTION_PREFLIGHT)
        return dnfast_set_error(error, DNFAST_STATUS_INVALID_ARGUMENT,
                                "rpm", "transaction", "transaction is not prepared");
    int32_t ignored = 0;
    if (attempt(context, test, run, result == NULL ? &ignored : result) != 0)
        return dnfast_set_error(error, DNFAST_STATUS_NATIVE_FAILURE,
                                "rpm", run ? "rpmtsRun" : "rpmtsCheck",
                                run && !test ? "real transaction failed; reconciliation required" :
                                ignored == 1 ? "preflight stage: rpmts setup" : ignored == 2 ? "preflight stage: write transaction" :
                                ignored == 3 ? "preflight stage: item add" : ignored == 4 ? "preflight stage: rpmtsCheck" : "preflight stage: rpmtsOrder");
    return DNFAST_STATUS_OK;
#else
    return dnfast_set_error(error, DNFAST_STATUS_UNSUPPORTED_ABI,
                            "rpm", "rpmtsRun", "real native build disabled");
#endif
}
dnfast_status dnfast_transaction_prepare(dnfast_context *context, dnfast_error *error) {
    return execute(context, 1, 0, NULL, error);
}
dnfast_status dnfast_transaction_test(dnfast_context *context, int32_t *result,
                                      dnfast_error *error) {
    return execute(context, 1, 1, result, error);
}
dnfast_status dnfast_transaction_run(dnfast_context *context, int32_t *result,
                                     dnfast_error *error) {
    return execute(context, 0, 1, result, error);
}
