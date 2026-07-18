#ifndef DNFAST_NATIVE_H
#define DNFAST_NATIVE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define DNFAST_NATIVE_ABI_VERSION UINT32_C(4)

typedef enum dnfast_pool_architecture {
    DNFAST_POOL_ARCHITECTURE_INVALID = 0,
    DNFAST_POOL_ARCHITECTURE_AARCH64 = 1,
    DNFAST_POOL_ARCHITECTURE_X86_64 = 2
} dnfast_pool_architecture;

typedef enum dnfast_executor_approval {
    DNFAST_EXECUTOR_PROMPT = 0,
    DNFAST_EXECUTOR_ASSUME_YES = 1,
    DNFAST_EXECUTOR_ASSUME_NO = 2
} dnfast_executor_approval;

typedef struct dnfast_context dnfast_context;
typedef struct dnfast_keyring dnfast_keyring;

typedef enum dnfast_status {
    DNFAST_STATUS_OK = 0,
    DNFAST_STATUS_INVALID_ARGUMENT = 1,
    DNFAST_STATUS_UNSUPPORTED_ABI = 2,
    DNFAST_STATUS_LIMIT_EXCEEDED = 3,
    DNFAST_STATUS_CALLBACK_FAILED = 4,
    DNFAST_STATUS_INTERRUPTED = 5,
    DNFAST_STATUS_WRONG_THREAD = 6,
    DNFAST_STATUS_NATIVE_FAILURE = 7,
    DNFAST_STATUS_PERMISSION_DENIED = 8,
    DNFAST_STATUS_LOCK_TIMEOUT = 9
} dnfast_status;

typedef struct dnfast_error {
    dnfast_status status;
    char *component;
    char *symbol;
    char *message;
} dnfast_error;

dnfast_status dnfast_modulemd_parse_json(const uint8_t *yaml,
                                         size_t yaml_size,
                                         char **json,
                                         dnfast_error *out_error);
void dnfast_string_free(char *value);

typedef struct dnfast_limits {
    uint32_t abi_version;
    uint32_t max_packages;
    uint32_t max_relations_per_package;
    uint32_t pool_architecture;
    uint64_t max_metadata_bytes;
} dnfast_limits;

typedef dnfast_status (*dnfast_interrupt_fn)(void *user_data);
typedef dnfast_status (*dnfast_transaction_start_fn)(void *user_data);

typedef struct dnfast_callbacks {
    uint32_t abi_version;
    void *user_data;
    dnfast_interrupt_fn interrupt;
    dnfast_transaction_start_fn transaction_start;
} dnfast_callbacks;

typedef struct dnfast_repo_input {
    uint32_t abi_version;
    const char *id;
    const char *repomd_path;
    const char *primary_path;
    const char *filelists_path;
    int32_t priority;
    int32_t cost;
    uint8_t installed;
} dnfast_repo_input;

typedef struct dnfast_repo_package {
    const char *name;
    const char *arch;
    const char *evr;
    const char *vendor;
    uint64_t package_size;
    uint64_t installed_size;
    size_t checksum_size;
    size_t location_size;
    size_t relation_counts[4];
    size_t relation_bytes[4];
} dnfast_repo_package;

typedef struct dnfast_solve_request {
    uint32_t abi_version;
    const char *const *names;
    size_t name_count;
    uint8_t install_weak_deps;
    uint8_t best;
} dnfast_solve_request;

typedef struct dnfast_solvable_reference {
    const char *repository_id;
    uint32_t package_ordinal;
    const char *expected_identity;
} dnfast_solvable_reference;

typedef struct dnfast_selector_providers {
    size_t selector_index;
    const dnfast_solvable_reference *providers;
    size_t provider_count;
} dnfast_selector_providers;

typedef struct dnfast_inventory_record {
    const char *name;
    const char *version;
    const char *release;
    const char *arch;
    const char *vendor;
    uint32_t epoch;
    uint64_t db_instance;
    uint64_t install_time;
    const uint8_t *immutable_header;
    size_t immutable_header_size;
} dnfast_inventory_record;

/*
 * ABI ownership and execution contract:
 * - Callers zero-initialize dnfast_error before first use and release its owned
 *   strings exactly once with dnfast_error_free; free functions accept NULL.
 * - A successful open uniquely transfers the opaque context to the caller.
 * - Context calls and destruction occur on the thread that opened the context.
 * - Callback storage remains valid until context destruction. Callbacks execute
 *   synchronously on the owner thread, must not re-enter the context, and signal
 *   interruption only by returning DNFAST_STATUS_INTERRUPTED.
 * - Limits are copied during open. ABI/version and dynamic dependency checks
 *   complete before the context allocation is attempted.
 */
dnfast_limits dnfast_limits_default(void);
void dnfast_release_unused_memory(void);
/*
 * Linux fs-verity helpers used by the immutable solv cache.  Enable returns
 * 1 when verity is enabled (including an already-enabled file), 0 when the
 * backing filesystem has no fs-verity support, and -1 on any other error.
 * Measure returns 1 and a 32-byte SHA-256 fs-verity digest, 0 when verity is
 * absent/unsupported, and -1 on error.
 */
int dnfast_fsverity_enable(int retained_fd);
int dnfast_fsverity_measure(int retained_fd, uint8_t digest[32]);
dnfast_status dnfast_context_open(const dnfast_limits *limits,
                                  const dnfast_callbacks *callbacks,
                                  dnfast_context **out_context,
                                  dnfast_error *out_error);
int dnfast_executor_exec_fixed(int plan_fd, uint8_t approval);
int dnfast_executor_exec_compact(int plan_fd, int manifest_fd,
                                 const int *artifact_fds,
                                 size_t artifact_count, uint8_t approval);
dnfast_status dnfast_context_check(dnfast_context *context,
                                   dnfast_error *out_error);
const char *dnfast_context_pool_architecture(const dnfast_context *context);
dnfast_status dnfast_solver_add_repo(dnfast_context *context,
                                     const dnfast_repo_input *input,
                                     dnfast_error *out_error);
dnfast_status dnfast_solver_add_repo_primary(dnfast_context *context,
                                             const dnfast_repo_input *input,
                                             dnfast_error *out_error);
dnfast_status dnfast_solver_add_repo_solv(
    dnfast_context *context, const dnfast_repo_input *input, int retained_fd,
    const uint8_t *expected_userdata, size_t expected_userdata_size,
    dnfast_error *out_error);
dnfast_status dnfast_solver_write_repo_solv(
    dnfast_context *context, const char *repository_id, int retained_fd,
    const uint8_t *userdata, size_t userdata_size, dnfast_error *out_error);
size_t dnfast_solver_repo_package_count(const dnfast_context *context,
                                        const char *repository_id);
dnfast_status dnfast_solver_repo_package_find_identity(
    dnfast_context *context, const char *repository_id, const char *identity,
    size_t *ordinal, dnfast_error *out_error);
dnfast_status dnfast_solver_repo_package_next_name(
    dnfast_context *context, const char *repository_id, const char *name,
    size_t start_ordinal, size_t *ordinal, uint8_t *found,
    dnfast_error *out_error);
dnfast_status dnfast_solver_repo_package_get(
    dnfast_context *context, const char *repository_id, size_t ordinal,
    dnfast_repo_package *package, dnfast_error *out_error);
dnfast_status dnfast_solver_repo_package_catalog_get(
    dnfast_context *context, const char *repository_id, size_t ordinal,
    dnfast_repo_package *package, dnfast_error *out_error);
dnfast_status dnfast_solver_repo_package_payload(
    dnfast_context *context, const char *repository_id, size_t ordinal,
    uint8_t *payload, size_t payload_size, dnfast_error *out_error);
dnfast_status dnfast_solver_repo_package_relations(
    dnfast_context *context, const char *repository_id, size_t ordinal,
    uint8_t kind, uint8_t *relations, size_t relation_size,
    dnfast_error *out_error);
uint8_t dnfast_solver_has_provider(const dnfast_context *context,
                                   const char *capability);
dnfast_status dnfast_solver_add_rpmdb(dnfast_context *context,
                                      const char *root,
                                      dnfast_error *out_error);
dnfast_status dnfast_solver_prepare(dnfast_context *context,
                                    dnfast_error *out_error);
dnfast_status dnfast_solver_set_module_excludes(
    dnfast_context *context, const char *const *nevras, size_t nevra_count,
    dnfast_error *out_error);
void dnfast_solver_release_result(dnfast_context *context);
dnfast_status dnfast_inventory_read(dnfast_context *context,
                                    const char *root,
                                    dnfast_error *out_error);
dnfast_status dnfast_inventory_read_cached(dnfast_context *context,
                                            const char *root,
                                            const char *expected_cookie,
                                            uint8_t *cache_hit,
                                            dnfast_error *out_error);
dnfast_status dnfast_inventory_verify_db(dnfast_context *context,
                                         const char *root,
                                         dnfast_error *out_error);
dnfast_status dnfast_inventory_write_begin(dnfast_context *context,
                                           dnfast_keyring *keyring,
                                           const char *root,
                                           uint64_t timeout_milliseconds,
                                           dnfast_error *out_error);
dnfast_status dnfast_inventory_read_locked(dnfast_context *context,
                                           dnfast_error *out_error);
dnfast_status dnfast_inventory_read_locked_cached(dnfast_context *context,
                                                  const char *expected_cookie,
                                                  uint8_t *cache_hit,
                                                  dnfast_error *out_error);
dnfast_status dnfast_inventory_read_locked_selected(dnfast_context *context,
                                                    const char *const *names,
                                                    size_t name_count,
                                                    dnfast_error *out_error);
void dnfast_inventory_write_end(dnfast_context *context);
uint64_t dnfast_inventory_rpm_run_count(const dnfast_context *context);
uint64_t dnfast_inventory_test_count(const dnfast_context *context);
uint64_t dnfast_inventory_real_count(const dnfast_context *context);
dnfast_status dnfast_inventory_test_run(dnfast_context *context,
                                        int32_t *rpm_result,
                                        dnfast_error *out_error);
dnfast_status dnfast_inventory_run(dnfast_context *context,
                                   int32_t *rpm_result,
                                   dnfast_error *out_error);
dnfast_status dnfast_keyring_fixture_open(dnfast_keyring **keyring,
                                          dnfast_error *out_error);
typedef struct dnfast_key_blob {
    const uint8_t *data;
    size_t length;
} dnfast_key_blob;
typedef struct dnfast_verified_package {
    char name[256];
    char epoch[32];
    char version[256];
    char release[256];
    char arch[64];
    char vendor[256];
    char primary_fingerprint[41];
    char signing_fingerprint[41];
} dnfast_verified_package;
typedef struct dnfast_transaction_install {
    dnfast_verified_package package;
    uint8_t artifact_sha256[32];
    uint64_t artifact_size;
    /* 0 install, 1 upgrade, 2 reinstall, 3 downgrade. */
    uint8_t upgrade;
} dnfast_transaction_install;
typedef enum dnfast_transaction_phase {
    DNFAST_TRANSACTION_PREFLIGHT = 0,
    DNFAST_TRANSACTION_STARTED = 1
} dnfast_transaction_phase;
typedef struct dnfast_transaction_counts {
    uint64_t fd_open;
    uint64_t fd_close;
    uint64_t open_attempted;
    uint64_t open_failed;
    uint64_t rewind_attempted;
    uint64_t rewind_succeeded;
    uint64_t rewind_failed;
    uint64_t close_attempted;
    uint64_t close_failed;
    uint64_t script_start;
    uint64_t script_stop;
    uint64_t package_stop;
    uint64_t test_run;
    uint64_t real_run;
} dnfast_transaction_counts;
dnfast_status dnfast_keyring_open(const dnfast_key_blob *keys, size_t count,
                                  dnfast_keyring **keyring,
                                  dnfast_error *out_error);
dnfast_status dnfast_keyring_verify_fd(dnfast_keyring *keyring, int fd,
                                       dnfast_verified_package *package,
                                       dnfast_error *out_error);
void dnfast_keyring_free(dnfast_keyring *keyring);
dnfast_status dnfast_transaction_add_install(
    dnfast_context *context, dnfast_keyring *keyring, int retained_fd,
    const dnfast_transaction_install *expected,
    dnfast_error *out_error);
dnfast_status dnfast_transaction_add_erase(
    dnfast_context *context, uint64_t db_instance,
    const uint8_t immutable_header_sha256[32], dnfast_error *out_error);
dnfast_status dnfast_transaction_prepare(dnfast_context *context,
                                         dnfast_error *out_error);
dnfast_status dnfast_transaction_test(dnfast_context *context,
                                      int32_t *rpm_result,
                                      dnfast_error *out_error);
dnfast_status dnfast_transaction_run(dnfast_context *context,
                                     int32_t *rpm_result,
                                     dnfast_error *out_error);
dnfast_status dnfast_transaction_verify_db(dnfast_context *context,
                                           dnfast_error *out_error);
size_t dnfast_transaction_problem_count(const dnfast_context *context);
const char *dnfast_transaction_problem(const dnfast_context *context,
                                       size_t index);
dnfast_transaction_counts dnfast_transaction_get_counts(
    const dnfast_context *context);
dnfast_transaction_phase dnfast_transaction_get_phase(
    const dnfast_context *context);
void dnfast_transaction_fixture_fail_callback(dnfast_context *context,
                                              uint8_t point);
uint64_t dnfast_inventory_keyring_sequence(const dnfast_context *context);
uint64_t dnfast_inventory_rpmdb_sequence(const dnfast_context *context);
void dnfast_inventory_fixture_fail_next_test(dnfast_context *context);
void dnfast_inventory_fixture_reset_global_counts(void);
uint64_t dnfast_inventory_fixture_global_test_count(void);
uint64_t dnfast_inventory_fixture_global_real_count(void);
const char *dnfast_inventory_backend(const dnfast_context *context);
const char *dnfast_inventory_cookie(const dnfast_context *context);
const char *dnfast_inventory_rpm_version(const dnfast_context *context);
size_t dnfast_inventory_count(const dnfast_context *context);
const dnfast_inventory_record *dnfast_inventory_get(
    const dnfast_context *context, size_t index);
dnfast_status dnfast_solver_solve_install(dnfast_context *context,
                                          const dnfast_solve_request *request,
                                          dnfast_error *out_error);
dnfast_status dnfast_solver_solve_operation(dnfast_context *context,
                                            const dnfast_solve_request *request,
                                            uint8_t operation,
                                            dnfast_error *out_error);
dnfast_status dnfast_solver_solve_mapped_operation(
    dnfast_context *context,
    const dnfast_solve_request *request,
    const dnfast_selector_providers *selectors,
    size_t selector_count,
    uint8_t operation,
    dnfast_error *out_error);
size_t dnfast_solver_action_count(const dnfast_context *context);
const char *dnfast_solver_action(const dnfast_context *context, size_t index);
const char *dnfast_solver_action_repo(const dnfast_context *context, size_t index);
const char *dnfast_solver_action_kind(const dnfast_context *context, size_t index);
const char *dnfast_solver_action_obsoletes(const dnfast_context *context, size_t index);
const char *dnfast_solver_action_requested_spec(const dnfast_context *context,
                                                size_t index);
uint8_t dnfast_solver_action_requested_relation_kind(const dnfast_context *context,
                                                     size_t index);
size_t dnfast_solver_satisfied_spec_count(const dnfast_context *context);
const char *dnfast_solver_satisfied_spec(const dnfast_context *context,
                                         size_t index);
size_t dnfast_solver_decision_count(const dnfast_context *context);
const char *dnfast_solver_decision_requiring(const dnfast_context *context, size_t index);
const char *dnfast_solver_decision_provider(const dnfast_context *context, size_t index);
const char *dnfast_solver_decision_relation(const dnfast_context *context, size_t index);
uint8_t dnfast_solver_decision_kind(const dnfast_context *context, size_t index);
uint8_t dnfast_solver_decision_provider_installed(const dnfast_context *context, size_t index);
size_t dnfast_solver_problem_count(const dnfast_context *context);
const char *dnfast_solver_problem(const dnfast_context *context, size_t index);
void dnfast_context_free(dnfast_context *context);
uint64_t dnfast_context_allocation_count(void);
void dnfast_error_free(dnfast_error *error);
int dnfast_executor_take_plan_fd(void);
int dnfast_executor_take_compact_fd(void);
int dnfast_executor_take_artifact_fd(size_t index);

#ifdef __cplusplus
}
#endif
#endif
