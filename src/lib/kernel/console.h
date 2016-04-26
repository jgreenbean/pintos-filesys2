#ifndef __LIB_KERNEL_CONSOLE_H
#define __LIB_KERNEL_CONSOLE_H

void console_init (void);
void console_panic (void);
void console_print_stats (void);
long long written_chars(void);

#endif /* lib/kernel/console.h */
