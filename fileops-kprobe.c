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

#include "./util.h"
#include <linux/mutex.h>
#include <linux/rwlock.h>
#include <linux/string.h>

#define MAX_SYMBOL_LEN	64
#define MONITOR_PATH "/home/jt/"  // 指定需要监控的目录

static DEFINE_MUTEX(kmutex);
static rwlock_t write_lock;
static char symbol[MAX_SYMBOL_LEN] = "vfs_write";
module_param_string(symbol, symbol, sizeof(symbol), 0644);
static char target_dir[PATH_MAX] = MONITOR_PATH;
module_param_string(target_dir, target_dir, sizeof(target_dir), 0644);

/* For each probe you need to allocate a kprobe structure */
static struct kprobe kp = {
	.symbol_name	= symbol,
};

static char *f_get_path(const struct file *file, char *buf, int buflen)
{
	char *pathstr = DEFAULT_RET_STR;
	if (buf) {
		pathstr = d_path(&(file->f_path), buf, buflen);
		if (IS_ERR(pathstr))
			pathstr = NAME_TOO_LONG;
	}
	return pathstr;
}

static loff_t get_file_size(const struct file *file){
	struct kstat stat;
	int ret;
	ret = vfs_getattr(&(file->f_path), &stat, STATX_SIZE, AT_STATX_SYNC_AS_STAT);

	if (ret)
		return -ret;
	//获取文件大小
	return stat.size;
}

// int checkCPUendian(void) {
//     union {
//         unsigned long int i;
//         unsigned char s[4];
//     } c;
//     c.i = 0x12345678;
//     return (0x12 == c.s[0]);
// }

/* kprobe pre_handler: called just before the probed instruction is executed */
static int __kprobes write_handler_pre(struct kprobe *p, struct pt_regs *regs)
{
	struct file *file = (struct file *)regs_get_arg1(regs);//因为x86的参数传递规则是di，si，dx，cx，r8，r9，所以di就是vfs_write的第一个参数。arm默认是r0，r1，r2，r3，相应的取r0
    // static struct event_context *event;
	// const char __user *buf;
	// char *kbuf = NULL;
	char *pname_buf = NULL;
	char *filepath = DEFAULT_RET_STR;
	char *proc_name;
	char *parent_proc;
	char *f_op;
	char *f_name;
	struct kstat stat;
	unsigned long ino;
	size_t len = (size_t)regs_get_arg3(regs);
	s64 timestamp;

    // 写锁保护
    write_lock(&write_lock);

    // 只处理有效的文件写操作
    if (unlikely(len <= 0 || !S_ISREG(file_inode(file)->i_mode))) {
        write_unlock(&write_lock);
        return 0;
    }

    // 分配路径缓冲区
    pname_buf = f_kzalloc(PATH_MAX, GFP_ATOMIC);
    if (unlikely(!pname_buf)) {
        write_unlock(&write_lock);
        return 0;
    }

    // 获取文件路径
    filepath = f_get_path(file, pname_buf, PATH_MAX);
    if (unlikely(IS_ERR(filepath))) {
        kfree(pname_buf);
        write_unlock(&write_lock);
        return 0;
    }

    // 只监控特定目录的文件操作
    if (strncmp(filepath, MONITOR_PATH, strlen(MONITOR_PATH)) != 0) {
        kfree(pname_buf);
        write_unlock(&write_lock);
        return 0;  // 如果文件路径不匹配，则直接返回
    }

	stat.size = get_file_size(file);
	if (unlikely(stat.size <= 0)){
		kfree(pname_buf);
		write_unlock(&write_lock);
		return 0;
	}

    // 记录进程和文件信息
    proc_name = current->comm;
    parent_proc = current->real_parent->comm;
    f_op = (char *)kp.symbol_name;
    f_name = (char *)file->f_path.dentry->d_name.name;
    ino = file->f_inode->i_ino;
    timestamp = (s64)ktime_get_real_seconds();

    // 打印信息
    pr_info("process_name:%s\tprocess_parent:%s\tfile_op: %s\tfile_name:%s\tfile_path:%s\tsize: %lld Bytes\tinode:%lu\taccess_time:%lld\t\n",
            proc_name, parent_proc, f_op, f_name, filepath, stat.size, ino, timestamp);

    // 释放资源
    kfree(pname_buf);
    write_unlock(&write_lock);

    return 0;
}

/* kprobe post_handler: called after the probed instruction is executed */


static int __init kprobe_init(void)
{
	int ret;
	kp.pre_handler = write_handler_pre;
	mutex_init(&kmutex);
	rwlock_init(&write_lock);
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
	mutex_unlock(&kmutex);
	pr_info("kprobe at %p unregistered\n", kp.addr);
}

module_init(kprobe_init)
module_exit(kprobe_exit)
MODULE_LICENSE("GPL");
