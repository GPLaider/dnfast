#include "internal.h"

dnfast_status dnfast_callback_check(const dnfast_callbacks *callbacks,
                                    dnfast_error *error) {
    if (callbacks->interrupt == NULL) {
        return DNFAST_STATUS_OK;
    }
    dnfast_status status = callbacks->interrupt(callbacks->user_data);
    if (status == DNFAST_STATUS_OK || status == DNFAST_STATUS_INTERRUPTED) {
        return status;
    }
    return dnfast_set_error(error, DNFAST_STATUS_CALLBACK_FAILED, "callback",
                            "interrupt", "callback returned an invalid status");
}
