#ifndef _LINUX_RESCTRL_H
#define _LINUX_RESCTRL_H

#ifdef CONFIG_X86
extern void rdtgroup_fork(struct task_struct *child);
extern void rdtgroup_exit(struct task_struct *tsk);
#else
static inline void rdtgroup_fork(struct task_struct *child) {}
static inline void rdtgroup_exit(struct task_struct *tsk) {}
#endif /* CONFIG_X86 */

#endif /* _LINUX_RESCTRL_H */
