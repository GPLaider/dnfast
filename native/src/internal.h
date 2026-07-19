#ifndef DNFAST_NATIVE_INTERNAL_H
#define DNFAST_NATIVE_INTERNAL_H

#include "dnfast_native.h"

#include <pthread.h>
#include <stdio.h>
#include <sys/stat.h>
#ifdef DNFAST_NATIVE_REAL
#include <solv/bitmap.h>
#include <solv/pooltypes.h>
#include <rpm/rpmts.h>
#include <rpm/header.h>
#include <rpm/rpmio.h>
#include <rpm/rpmkeyring.h>
#endif

typedef struct dnfast_library {
    void *handle;
    const char *component;
} dnfast_library;
struct s_Repo;
struct s_Solvable;
#ifdef DNFAST_NATIVE_REAL
typedef struct dnfast_transaction_item {
    int retained_fd;
    dev_t device;
    ino_t inode;
    dnfast_transaction_install expected;
    uint8_t erase;
    uint32_t db_instance;
    uint8_t header_sha256[32];
    FD_t active_fd;
} dnfast_transaction_item;
#endif

struct dnfast_context {
    dnfast_library libraries[4];
    dnfast_callbacks callbacks;
    pthread_t owner;
    dnfast_limits limits;
    uint64_t metadata_bytes;
    uint32_t package_count;
#ifdef DNFAST_NATIVE_REAL
    struct s_Pool *pool;
    struct s_Solver *solver;
    struct s_Transaction *transaction;
    Map *module_considered;
    rpmts inventory_write_ts;
    rpmtxn inventory_write_txn;
#endif
    char **actions;
    char **action_obsoletes;
    char **action_requested_specs;
    uint8_t *action_requested_relation_kinds;
    size_t action_count;
    char **satisfied_specs;
    size_t satisfied_spec_count;
    char **decision_requiring;
    char **decision_provider;
    char **decision_relation;
    uint8_t *decision_kind;
    uint8_t *decision_installed;
    size_t decision_count;
    size_t decision_capacity;
    char **problems;
    size_t problem_count;
    dnfast_inventory_record *inventory;
    size_t inventory_count;
    char *inventory_backend;
    char *inventory_cookie;
    uint64_t inventory_rpm_run_count;
    uint64_t inventory_test_count;
    uint64_t inventory_real_count;
    uint64_t inventory_keyring_sequence;
    uint64_t inventory_rpmdb_sequence;
    int inventory_fail_next_test;
#ifdef DNFAST_NATIVE_REAL
    dnfast_transaction_item **transaction_items;
    size_t transaction_item_count;
    char **transaction_problems;
    size_t transaction_problem_count;
    dnfast_transaction_counts transaction_counts;
    dnfast_transaction_phase transaction_phase;
    rpmKeyring transaction_keyring;
    dnfast_keyring *transaction_identity_keyring;
    uint8_t transaction_fail_callback;
    uint8_t transaction_callback_failed;
#endif
};

#ifdef DNFAST_NATIVE_REAL
typedef struct dnfast_signer_identity {
    char key_id[17];
    char primary[41];
    char signing[41];
} dnfast_signer_identity;
struct dnfast_keyring {
    rpmKeyring value;
    dnfast_signer_identity *identities;
    size_t identity_count;
};
int dnfast_keyring_import_armor(dnfast_keyring *ring,
                                const dnfast_key_blob *blob);
const dnfast_signer_identity *dnfast_keyring_find_signer(
    const dnfast_keyring *ring, Header header);
const dnfast_signer_identity *dnfast_keyring_find_encoded_signer(
    const dnfast_keyring *ring, const char *encoded);
const dnfast_signer_identity *dnfast_keyring_find_packet_signer(
    const dnfast_keyring *ring, const uint8_t *packet, size_t packet_len);
const dnfast_signer_identity *dnfast_keyring_find_fd_signer(
    const dnfast_keyring *ring, int fd);
int dnfast_verify_payload_digest(int fd, Header header);
#else
struct dnfast_keyring { void *value; };
#endif

dnfast_status dnfast_load_libraries(dnfast_library libraries[4],
                                    dnfast_error *error);
void dnfast_unload_libraries(dnfast_library libraries[4]);
dnfast_status dnfast_set_error(dnfast_error *error, dnfast_status status,
                               const char *component, const char *symbol,
                               const char *message);
dnfast_status dnfast_callback_check(const dnfast_callbacks *callbacks,
                                    dnfast_error *error);
void dnfast_solver_clear(dnfast_context *context);
#ifdef DNFAST_NATIVE_REAL
dnfast_status dnfast_decisions_collect(dnfast_context *context, dnfast_error *error);
char *dnfast_solvable_identity(struct s_Pool *pool, struct s_Solvable *item);
#endif
void dnfast_inventory_clear(dnfast_context *context);
#ifdef DNFAST_NATIVE_REAL
dnfast_status dnfast_inventory_prepare_rpm(dnfast_error *error);
void dnfast_inventory_configure_trusted_rpmdb_read(rpmts ts);
char *dnfast_inventory_take_cookie(rpmts ts);
dnfast_status dnfast_inventory_collect(dnfast_context *context, rpmts ts,
                                       dnfast_error *error);
dnfast_status dnfast_inventory_collect_selected(dnfast_context *context, rpmts ts,
                                                const char *const *names,
                                                size_t name_count,
                                                dnfast_error *error);
void dnfast_transaction_clear(dnfast_context *context);
int dnfast_transaction_reverify(dnfast_context *context,
                                dnfast_transaction_item *item);
FD_t dnfast_transaction_truncated_duplicate(const dnfast_transaction_item *item);
#endif
dnfast_status dnfast_metadata_open(const dnfast_repo_input *input,
                                   FILE *streams[3], struct stat identity[3],
                                   size_t stream_count,
                                   dnfast_error *error);
void dnfast_metadata_close(FILE *streams[3]);
dnfast_status dnfast_limits_before_repo(dnfast_context *context,
                                        const int metadata_fds[3],
                                        size_t metadata_count,
                                        dnfast_error *error);
dnfast_status dnfast_limits_finalize_repo(dnfast_context *context,
                                          struct s_Repo *repo,
                                          const dnfast_repo_input *input,
                                          FILE *streams[3],
                                          const struct stat identity[3],
                                          size_t metadata_count,
                                          dnfast_error *error);
dnfast_status dnfast_limits_finalize_loaded_repo(dnfast_context *context,
                                                 struct s_Repo *repo,
                                                 uint64_t metadata_bytes,
                                                 dnfast_error *error);
dnfast_status dnfast_limits_accept_validated_repo(dnfast_context *context,
                                                  struct s_Repo *repo,
                                                  uint64_t metadata_bytes,
                                                  dnfast_error *error);
dnfast_status dnfast_limits_accept_extension(dnfast_context *context,
                                             uint64_t metadata_bytes,
                                             dnfast_error *error);

#endif
