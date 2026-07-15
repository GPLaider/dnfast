#include <stddef.h>

void *pool_create(void) { return (void *)1; }
void pool_free(void *pool) { (void)pool; }
int repo_add_rpmmd(void) { return 0; }
void *rpmtsCreate(void) { return (void *)1; }
void *rpmtsFree(void *transaction) { return transaction; }
#ifndef DNFAST_HIDE_RPMTSRUN
int rpmtsRun(void) { return 0; }
#endif
int rpmioInit(void) { return 0; }
