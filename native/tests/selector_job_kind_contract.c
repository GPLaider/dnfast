#include <solv/pool.h>
#include <solv/queue.h>
#include <solv/solver.h>

int main(void) {
    Queue job;
    Id bare_dependency = 42;
    Id relation_dependency = MAKERELDEP(42);

    queue_init(&job);
    queue_push2(&job, SOLVER_SOLVABLE_NAME, bare_dependency);
    queue_push2(&job, SOLVER_SOLVABLE_NAME, relation_dependency);
    if (job.count != 4 || ISRELDEP(job.elements[1]) ||
        !ISRELDEP(job.elements[3])) {
        queue_free(&job);
        return 1;
    }
    queue_free(&job);
    return 0;
}
