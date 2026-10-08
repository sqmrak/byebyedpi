#ifndef SENKO_PROC_DETACH_H
#define SENKO_PROC_DETACH_H

/* leave the session of whoever started the daemon */
void senko_proc_detach(void);

/* lift a per-process jetsam limit below what a busy tunnel needs */
void senko_raise_memory_limit(void);

#endif
