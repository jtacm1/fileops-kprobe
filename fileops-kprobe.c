// SPDX-License-Identifier: GPL-2.0-only
/*
 * Here's a sample kernel module showing the use of kprobes to dump a
 * stack trace and selected registers when kernel_clone() is called.
 *
 * For more information on theory of operation of kprobes, see
 * Documentation/trace/kprobes.rst
 *
 * You will see the trace data in /var/log/messages and on the console
 * whenever kernel_clone() is invoked to create a new process.
 */

#define pr_fmt(fmt) "%s: " fmt, __func__

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
// #include <linux/kallsyms.h>
// #include <linux/fs.h>

#define DEFAULT_RET_STR "-2"
#define MAX_SYMBOL_LEN	64
static char symbol[MAX_SYMBOL_LEN] = "vfs_write";
module_param_string(symbol, symbol, sizeof(symbol), 0644);

/* For each probe you need to allocate a kprobe structure */
static struct kprobe kp = {
	.symbol_name	= symbol,
};
struct event_context {
	char * process_name;	//进程名
	char * process_parent; //父进程名
	const char * access_op;	//访问操作
	const char * file_name;     //文件名
	char * file_path;     //文件路径
	size_t size;  //文件大小
	unsigned long inode;  //文件inode
	s64 access_time; //访问时间
} event_context;
/* kprobe pre_handler: called just before the probed instruction is executed */
static int __kprobes write_handler_pre(struct kprobe *p, struct pt_regs *regs)
{
	const struct file *file = (struct file *)regs->di;//因为x86的参数传递规则是di，si，dx，cx，r8，r9，所以di就是vfs_write的第一个参数。arm默认是r0，r1，r2，r3，相应的取r0
    static struct event_context *event;
	char *buf;
    size_t size = 0;
	char *filepath = DEFAULT_RET_STR;
	//pr_info("<%s> p->addr = 0x%p, ip = %lx, flags = 0x%lx\n",
	//	p->symbol_name, p->addr, regs->ip, regs->flags);
	buf = kmalloc(PATH_MAX, GFP_ATOMIC);
	size = regs->dx;//vfs_write的第三个参数在dx中
    //pr_info("process = %s , pid = %d, process_parent = %s, file = %s, size = %ld\n" , current->comm, current->pid, current->real_parent->comm, file->f_path.dentry->d_name.name, size);	
	event = kmalloc(sizeof(struct event_context), GFP_ATOMIC);
	event->process_name = current->comm; //记录进程名
	event->process_parent = current->real_parent->comm; //记录父进程名
	event->access_op = kp.symbol_name;
	event->file_name = file->f_path.dentry->d_name.name; //记录文件名
	filepath = d_path(&(file->f_path), buf, PATH_MAX); //记录文件路径
	event->file_path = filepath;
	event->size = size; //记录文件大小
	if (size <= 0 && !S_ISREG(file_inode(file)->i_mode))
		return 0;
	
	event->inode = (file->f_inode)->i_ino; //记录文件inode
	event->access_time = (s64)ktime_get_real_seconds(); //记录访问时间
	pr_info("process_name:%s\tprocess_parent:%s\tfile_op: %s\tfile_name:%s\tfile_path:%s\tsize:%ld\tinode:%lu\taccess_time:%lld\t\n", 
	event->process_name, event->process_parent, event->access_op, event->file_name, event->file_path, event->size, event->inode, event->access_time);
	return 0;
}

/* kprobe post_handler: called after the probed instruction is executed */
static void __kprobes write_handler_post(struct kprobe *p, struct pt_regs *regs,
				unsigned long flags)
{

}

static int __init kprobe_init(void)
{
	int ret;
	kp.pre_handler = write_handler_pre;
	kp.post_handler = write_handler_post;

	ret = register_kprobe(&kp);
	if (ret < 0) {
		pr_err("register_kprobe failed, returned %d\n", ret);
		return ret;
	}
	pr_info("Planted kprobe at %p\n", kp.addr);
	return 0;
}

static void __exit kprobe_exit(void)
{
	unregister_kprobe(&kp);
	pr_info("kprobe at %p unregistered\n", kp.addr);
}

module_init(kprobe_init)
module_exit(kprobe_exit)
MODULE_LICENSE("GPL");
