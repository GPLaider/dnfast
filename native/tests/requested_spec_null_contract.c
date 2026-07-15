#include "internal.h"

#include <string.h>

int main(void) {
    dnfast_context failed_after_copy_actions;
    char selector[] = "dnfast-upgrade = 1.0-1";
    char *requested_specs[] = {selector};
    uint8_t requested_relation_kinds[] = {1};

    memset(&failed_after_copy_actions, 0, sizeof(failed_after_copy_actions));
    failed_after_copy_actions.action_count = 1;
    if (dnfast_solver_action_requested_spec(NULL, 0) != NULL ||
        dnfast_solver_action_requested_spec(&failed_after_copy_actions, 0) != NULL ||
        dnfast_solver_action_requested_spec(&failed_after_copy_actions, 1) != NULL ||
        dnfast_solver_action_requested_relation_kind(NULL, 0) != 0 ||
        dnfast_solver_action_requested_relation_kind(&failed_after_copy_actions, 0) != 0 ||
        dnfast_solver_action_requested_relation_kind(&failed_after_copy_actions, 1) != 0)
        return 1;
    failed_after_copy_actions.action_requested_specs = requested_specs;
    failed_after_copy_actions.action_requested_relation_kinds =
        requested_relation_kinds;
    return dnfast_solver_action_requested_spec(&failed_after_copy_actions, 0) == selector &&
            dnfast_solver_action_requested_spec(&failed_after_copy_actions, 1) == NULL &&
            dnfast_solver_action_requested_relation_kind(&failed_after_copy_actions, 0) == 1 &&
            dnfast_solver_action_requested_relation_kind(&failed_after_copy_actions, 1) == 0
        ? 0 : 1;
}
