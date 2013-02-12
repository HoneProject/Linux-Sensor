/*
 * Copyright (C) 2011 Battelle Memorial Institute <http://www.battelle.org>
 *
 * Author: Brandon Carpenter
 *
 * This package is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * 
 * This package is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/notifier.h>

#if !defined(CONFIG_KPROBES) || !defined(CONFIG_KRETPROBES) || !defined(CONFIG_KALLSYMS)
#error process_notify module requires kprobes support (CONFIG_KPROBES, CONFIG_KRETPROBES and CONFIG_KALLSYMS)
#endif

#include "process_notify.h"
#include "version.h"

static RAW_NOTIFIER_HEAD(notifier_list);
static DEFINE_RWLOCK(notifier_lock);

int process_notifier_register(struct notifier_block *nb)
{
	int result;
	unsigned long flags;

	write_lock_irqsave(&notifier_lock, flags);
	result = raw_notifier_chain_register(&notifier_list, nb);
	write_unlock_irqrestore(&notifier_lock, flags);
	return result;
}

int process_notifier_unregister(struct notifier_block *nb)
{
	int result;
	unsigned long flags;

	write_lock_irqsave(&notifier_lock, flags);
	result = raw_notifier_chain_unregister(&notifier_list, nb);
	write_unlock_irqrestore(&notifier_lock, flags);
	return result;
}

static inline int process_notifier_notify(
		unsigned long event, struct task_struct *task)
{
	int result;
	unsigned long flags;

	read_lock_irqsave(&notifier_lock, flags);
	result = raw_notifier_call_chain(&notifier_list, event, task);
	read_unlock_irqrestore(&notifier_lock, flags);
	return result;
}

static int fork_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	process_notifier_notify(PROC_FORK,
			(struct task_struct *) regs_return_value(regs));
	return 0;
}

static int exec_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	process_notifier_notify(PROC_EXEC, current);
	return 0;
}

static int exit_handler(struct kprobe *kp, struct pt_regs *regs)
{
	process_notifier_notify(PROC_EXIT, current);
	return 0;
}

extern void copy_process(void);
extern void compat_do_execve(void);

static struct kretprobe fork_kretprobe = {
	//.kp.symbol_name = "copy_process",
	.kp.addr = (kprobe_opcode_t *) copy_process,
	.handler = fork_handler,
};

static struct kretprobe exec_kretprobe = {
	//.kp.symbol_name = "do_execve",
	.kp.addr = (kprobe_opcode_t *) do_execve,
	.handler = exec_handler,
};

#ifdef CONFIG_COMPAT
static struct kretprobe compat_exec_kretprobe = {
	//.kp.symbol_name = "compat_do_execve",
	.kp.addr = (kprobe_opcode_t *) compat_do_execve,
	.handler = exec_handler,
};
#endif

static struct kprobe exit_kprobe = {
	//.symbol_name = "do_exit",
	.addr = (kprobe_opcode_t *) do_exit,
	.pre_handler = exit_handler,
};

int process_notify_init(void)
{
	int err;

	if ((err = register_kprobe(&exit_kprobe))) {
		printk(KERN_ERR "%s: exit register_kprobe() failed with error %d\n",
				THIS_MODULE->name, err);
		goto exit_failed;
	}
	if ((err = register_kretprobe(&fork_kretprobe))) {
		printk(KERN_ERR "%s: fork register_kretprobe() failed with error %d\n",
				THIS_MODULE->name, err);
		goto fork_failed;
	}
	if ((err = register_kretprobe(&exec_kretprobe))) {
		printk(KERN_ERR "%s: exec register_kretprobe() failed with error %d\n",
				THIS_MODULE->name, err);
		goto exec_failed;
	}
#ifdef CONFIG_COMPAT
	if ((err = register_kretprobe(&compat_exec_kretprobe))) {
		printk(KERN_ERR "%s: compat_exec register_kretprobe() failed with error %d\n",
				THIS_MODULE->name, err);
		if (err != -EINVAL)
			goto compat_exec_failed;
	}
#endif
	return 0;

#ifdef CONFIG_COMPAT
compat_exec_failed:
	unregister_kretprobe(&exec_kretprobe);
#endif
exec_failed:
	unregister_kretprobe(&fork_kretprobe);
fork_failed:
	unregister_kprobe(&exit_kprobe);
exit_failed:
	return err;
}

void process_notify_remove(void)
{
#ifdef CONFIG_COMPAT
	unregister_kretprobe(&compat_exec_kretprobe);
#endif
	unregister_kretprobe(&exec_kretprobe);
	unregister_kretprobe(&fork_kretprobe);
	unregister_kprobe(&exit_kprobe);
}

//#ifdef CONFIG_PROCESS_NOTIFY
static char version[] __initdata = HONE_VERSION;

static int __init process_notify_module_init(void)
{
	if (process_notify_init())
		return -1;
	printk("%s: v%s module successfully loaded\n", THIS_MODULE->name, version);
	return 0;
}

static void __exit process_notify_module_exit(void)
{
	process_notify_remove();
	printk("%s: module successfully unloaded\n", THIS_MODULE->name);
}

module_init(process_notify_module_init);
module_exit(process_notify_module_exit);

MODULE_DESCRIPTION("Process event notification module.");
MODULE_AUTHOR("Brandon Carpenter");
MODULE_LICENSE("GPL");
MODULE_VERSION(HONE_VERSION);

EXPORT_SYMBOL_GPL(process_notifier_register);
EXPORT_SYMBOL_GPL(process_notifier_unregister);
//#endif /* CONFIG_PROCESS_NOTIFY */

