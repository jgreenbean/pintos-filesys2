#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

typedef int pid_t;
#define PID_ERROR ((pid_t) -1)

/* Typical return values from main() and arguments to exit(). */
#define EXIT_SUCCESS 0          /* Successful execution. */
#define EXIT_FAILURE 1          /* Unsuccessful execution. */

#include "userprog/pagedir.h"

struct file;
void syscall_init (void);
uint32_t* lookup_page (uint32_t*, const void*, bool);
void exit (int status);

#endif /* userprog/syscall.h */
