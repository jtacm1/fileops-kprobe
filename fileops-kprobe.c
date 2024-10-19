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

// #define MAX_SYMBOL_LEN	64
#define MONITOR_PATH "/home/jt/下载/"  // 指定需要监控的目录
#define WRITE_OP "001"
#define READ_OP "002"
#define RENAME_OP "003"
#define CLOSE_OP "004"
#define CREATE_OP "005"
#define DELETE_OP "006"
#define OPEN_OP "007"
// static DEFINE_MUTEX(kmutex);
// static rwlock_t write_lock;
// static char symbol[MAX_SYMBOL_LEN] = "vfs_write";
// module_param_string(symbol, symbol, sizeof(symbol), 0644);
#define	RESULT_LEN	2048
static char target_dir[PATH_MAX] = MONITOR_PATH;
module_param_string(target_dir, target_dir, sizeof(target_dir), 0644);


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

// static loff_t get_file_size(const struct file *file){
// 	struct kstat stat;
// 	int ret;
// 	ret = vfs_getattr(&(file->f_path), &stat, STATX_SIZE, AT_STATX_SYNC_AS_STAT);

// 	if (ret)
// 		return -ret;
// 	//获取文件大小
// 	return stat.size;
// }

// int checkCPUendian(void) {
//     union {
//         unsigned long int i;
//         unsigned char s[4];
//     } c;
//     c.i = 0x12345678;
//     return (0x12 == c.s[0]);
// }

/* kprobe pre_handler: called just before the probed instruction is executed */
static int write_handler_pre(struct kprobe *p, struct pt_regs *regs)
{
	struct file *file = (struct file *)regs_get_arg1(regs);//因为x86的参数传递规则是di，si，dx，cx，r8，r9，所以di就是vfs_write的第一个参数。arm默认是r0，r1，r2，r3，相应的取r0
	char *result_str = NULL;
	char *pname_buf = NULL;
	char *filepath = DEFAULT_RET_STR;
	char *f_name = NULL;
	long long size;
	unsigned long ino;
	size_t len = (size_t)regs_get_arg3(regs);

    // 写锁保护
    // write_lock(&write_lock);

    // 只处理有效的文件写操作
    if (unlikely(len <= 0 || !S_ISREG(file_inode(file)->i_mode))) {
        // write_unlock(&write_lock);
        return 0;
    }

    // 分配路径缓冲区
    pname_buf = f_kzalloc(PATH_MAX, GFP_ATOMIC);
    if (unlikely(!pname_buf)) {
        // write_unlock(&write_lock);
        return 0;
    }

    // 获取文件路径
    filepath = f_get_path(file, pname_buf, PATH_MAX);
    if (unlikely(IS_ERR(filepath))) {
        kfree(pname_buf);
        // write_unlock(&write_lock);
        return 0;
    }

    // 只监控特定目录的文件操作
    if (strncmp(filepath, MONITOR_PATH, strlen(MONITOR_PATH)) != 0) {
        kfree(pname_buf);
        // write_unlock(&write_lock);
        return 0;  // 如果文件路径不匹配，则直接返回
    }

	size = file->f_path.dentry->d_inode->i_size;
	if (unlikely(size <= 0)){
		kfree(pname_buf);
		// write_unlock(&write_lock);
		return 0;
	}

    // 记录文件信息
    f_name = (char *)file->f_path.dentry->d_name.name;
    ino = file->f_inode->i_ino;

	result_str = kzalloc(RESULT_LEN, GFP_KERNEL);
	if (likely(result_str)){
		snprintf(result_str, RESULT_LEN, "process_name:%s\tprocess_parent:%s\nfile_op: %s\tfile_name:%s\tfile_path:%s\tsize: %lld Bytes\ninode:%lu\taccess_time:%lld\t\n",
				current->comm, current->real_parent->comm, WRITE_OP, f_name, filepath, size, ino, ktime_get_real_seconds());
	}

	// int str_len = strlen(result_str);
	// pr_info("result length: %d\n", str_len);
    // 打印信息
    // pr_info("process_name:%s\tprocess_parent:%s\tfile_op: %s\tfile_name:%s\tfile_path:%s\tsize: %lld Bytes\tinode:%lu\taccess_time:%lld\t\n",
    //         proc_name, parent_proc, f_op, f_name, filepath, stat.size, ino, timestamp);

	pr_info("%s",result_str);
    // 释放资源
    kfree(pname_buf);
	if (likely(result_str))
		kfree(result_str);
    // write_unlock(&write_lock);

    return 0;
}

static int read_handler_pre(struct kprobe *p, struct pt_regs *regs)
{
	struct file *file = (struct file *)regs_get_arg1(regs);//因为x86的参数传递规则是di，si，dx，cx，r8，r9，所以di就是vfs_write的第一个参数。arm默认是r0，r1，r2，r3，相应的取r0
	char *result_str = NULL;
	char *pname_buf = NULL;
	char *filepath = DEFAULT_RET_STR;
	char *f_name = NULL;
	long long size;
	unsigned long ino;
	size_t len = (size_t)regs_get_arg3(regs);

    // 写锁保护
    // write_lock(&write_lock);

    // 只处理有效的文件写操作
    if (unlikely(len <= 0 || !S_ISREG(file_inode(file)->i_mode))) {
        // write_unlock(&write_lock);
        return 0;
    }

    // 分配路径缓冲区
    pname_buf = f_kzalloc(PATH_MAX, GFP_ATOMIC);
    if (unlikely(!pname_buf)) {
        // write_unlock(&write_lock);
        return 0;
    }

    // 获取文件路径
    filepath = f_get_path(file, pname_buf, PATH_MAX);
    if (unlikely(IS_ERR(filepath))) {
        kfree(pname_buf);
        // write_unlock(&write_lock);
        return 0;
    }

    // 只监控特定目录的文件操作
    if (strncmp(filepath, MONITOR_PATH, strlen(MONITOR_PATH)) != 0) {
        kfree(pname_buf);
        // write_unlock(&write_lock);
        return 0;  // 如果文件路径不匹配，则直接返回
    }

	size = file->f_path.dentry->d_inode->i_size;
	if (unlikely(size <= 0)){
		kfree(pname_buf);
		// write_unlock(&write_lock);
		return 0;
	}

    // 记录文件信息
    f_name = (char *)file->f_path.dentry->d_name.name;
    ino = file->f_inode->i_ino;

	result_str = kzalloc(RESULT_LEN, GFP_KERNEL);
	if (likely(result_str)){
		snprintf(result_str, RESULT_LEN, "process_name:%s\tprocess_parent:%s\nfile_op: %s\tfile_name:%s\tfile_path:%s\tsize: %lld Bytes\ninode:%lu\taccess_time:%lld\t\n",
				current->comm, current->real_parent->comm, READ_OP, f_name, filepath, size, ino, ktime_get_real_seconds());
	}

	// int str_len = strlen(result_str);
	// pr_info("result length: %d\n", str_len);
    // 打印信息
    // pr_info("process_name:%s\tprocess_parent:%s\tfile_op: %s\tfile_name:%s\tfile_path:%s\tsize: %lld Bytes\tinode:%lu\taccess_time:%lld\t\n",
    //         proc_name, parent_proc, f_op, f_name, filepath, stat.size, ino, timestamp);

	pr_info("%s",result_str);
    // 释放资源
    kfree(pname_buf);
	if (likely(result_str))
		kfree(result_str);
    // write_unlock(&write_lock);

    return 0;
}

static int rename_handler_pre(struct kprobe *p, struct pt_regs *regs){
	struct dentry *old_dentry = (struct dentry *)regs_get_arg2(regs);
	struct inode *old_inode;
	struct dentry *new_dentry = (struct dentry *)regs_get_arg4(regs);
	char *old_name = NULL;
	char *new_name = NULL;
	char *result_str = NULL;
	char *pname_buf = NULL;
	char *filepath = DEFAULT_RET_STR;
	long long size;
	unsigned long ino;

	if (unlikely(!old_dentry || !(old_dentry->d_inode) || !S_ISREG(old_dentry->d_inode->i_mode)))
		return 0;
	else 
		old_inode = old_dentry->d_inode;
	if (unlikely(!new_dentry || !(new_dentry->d_inode) || !S_ISREG(new_dentry->d_inode->i_mode)))
	
	//获取原文件的路径
	pname_buf = kzalloc(PATH_MAX, GFP_KERNEL);
	if (unlikely(!pname_buf)) {
		return 0;
	}
	filepath = dentry_path_raw(old_dentry, pname_buf, PATH_MAX);
	if (unlikely(IS_ERR(filepath))) {
		kfree(pname_buf);
		return 0;
	}

	// 只监控特定目录的文件操作
    if (strncmp(filepath, MONITOR_PATH, strlen(MONITOR_PATH)) != 0) {
        kfree(pname_buf);
        // write_unlock(&write_lock);
        return 0;  // 如果文件路径不匹配，则直接返回
    }
	//获取原文件的文件名
	old_name = (char *)old_dentry->d_name.name;
	//获取原文件的inode号
	ino = (unsigned long)old_inode->i_ino;
	//获得文件大小
	size = old_dentry->d_inode->i_size;
	if (unlikely(size <= 0)){
		kfree(pname_buf);
		return 0;
	}
	//获取新文件名
	new_name = (char *)new_dentry->d_name.name;

	result_str = kzalloc(RESULT_LEN, GFP_KERNEL);
	if (likely(result_str)){
		snprintf(result_str, RESULT_LEN, "process_name:%s\tprocess_parent:%s\nfile_op: %s\told_name:%s\told_file_path:%s\tnew_file_name:%s\tsize: %lld Bytes\ninode:%lu\taccess_time:%lld\t\n",
				current->comm, current->real_parent->comm, RENAME_OP, old_name, filepath, new_name,size, ino, ktime_get_real_seconds());
	}

	pr_info("%s",result_str);
    // 释放资源
    kfree(pname_buf);
	if (likely(result_str))
		kfree(result_str);
    // write_unlock(&write_lock);

    return 0;

}

static int close_handler_pre(struct kprobe *p, struct pt_regs *regs){
	struct file *file = (struct file *)regs_get_arg1(regs);
	char *pname_buf = NULL;
	char *filepath = DEFAULT_RET_STR;
	char *result_str = NULL;
	char *f_name = NULL;
	long long size;
	unsigned long ino;
	
	//只处理有效文件的关闭操作
	if (unlikely(!S_ISREG(file_inode(file)->i_mode))) {
		return 0;	
	}
	
	// 分配路径缓冲区
    pname_buf = f_kzalloc(PATH_MAX, GFP_ATOMIC);
    if (unlikely(!pname_buf)) {
        // write_unlock(&write_lock);
        return 0;
    }

    // 获取文件路径
    filepath = f_get_path(file, pname_buf, PATH_MAX);
    if (unlikely(IS_ERR(filepath))) {
        kfree(pname_buf);
        // write_unlock(&write_lock);
        return 0;
    }

    // 只监控特定目录的文件操作
    if (strncmp(filepath, MONITOR_PATH, strlen(MONITOR_PATH)) != 0) {
        kfree(pname_buf);
        // write_unlock(&write_lock);
        return 0;  // 如果文件路径不匹配，则直接返回
    }
	//获取文件大小
	size = file->f_path.dentry->d_inode->i_size;
	if (unlikely(size <= 0)){
		kfree(pname_buf);
		return 0;
	}	
	//记录文件名和inode号
	f_name = (char *)file->f_path.dentry->d_name.name;
	ino = file->f_inode->i_ino;

	result_str = kzalloc(RESULT_LEN, GFP_KERNEL);
	if (likely(result_str)){
		snprintf(result_str, RESULT_LEN, "process_name:%s\tprocess_parent:%s\nfile_op: %s\tfile_name:%s\tfile_path:%s\tsize: %lld Bytes\ninode:%lu\taccess_time:%lld\t\n",
	        current->comm, current->real_parent->comm, CLOSE_OP, f_name, filepath, size, ino, ktime_get_real_seconds());
	}	
	pr_info("%s", result_str);
	kfree(pname_buf);
	if (likely(result_str))
		kfree(result_str);
	return 0;
}

static void create_handler_post(struct kprobe *p, struct pt_regs *regs, unsigned long flags){
	
	struct dentry *dentry = (struct dentry *)regs_get_arg2(regs);
	char *pname_buf = NULL;
	char *filepath = DEFAULT_RET_STR;
	char *result_str = NULL;
	char *f_name = NULL;
	long long size;
	unsigned long ino;

	//分配内存给文件路径缓冲区
	pname_buf = kzalloc(PATH_MAX, GFP_KERNEL);
	if (unlikely(!pname_buf)) {
		return;
	}

		//只处理有效的文件创建操作
	if (unlikely(IS_ERR_OR_NULL(dentry) || !(dentry->d_inode) || !S_ISREG(dentry->d_inode->i_mode))){
		kfree(pname_buf);
		return;	
	}
	//获取文件路径
	filepath = dentry_path_raw(dentry, pname_buf, PATH_MAX);
	if (unlikely(IS_ERR(filepath))) {
		kfree(pname_buf);
		return;
	}

	// 只监控特定目录的文件操作
	if (strncmp(filepath, MONITOR_PATH, strlen(MONITOR_PATH)) != 0) {
		kfree(pname_buf);
		return;  // 如果文件路径不匹配，则直接返回
	}
	//获取文件大小
	size = dentry->d_inode->i_size;
	if (unlikely(size <= 0)){
		kfree(pname_buf);
		return;
	}	
	//记录文件名和inode号
	f_name = (char *)dentry->d_name.name;
	ino = dentry->d_inode->i_ino;

	result_str = kzalloc(RESULT_LEN, GFP_KERNEL);
	if (likely(result_str)){
		snprintf(result_str, RESULT_LEN, "process_name:%s\tprocess_parent:%s\nfile_op: %s\tfile_name:%s\tfile_path:%s\tsize: %lld Bytes\ninode:%lu\taccess_time:%lld\t\n",
									current->comm, current->real_parent->comm, CREATE_OP, f_name, filepath, size, ino, ktime_get_real_seconds());
	}	
	pr_info("%s", result_str);
	//释放内存资源
	kfree(pname_buf);
	if (likely(result_str))
		kfree(result_str);
	
	return;
}

static int delete_handler_pre(struct kprobe *p, struct pt_regs *regs){
	struct dentry *dentry = (struct dentry *)regs_get_arg2(regs);
	char *pname_buf = NULL;
	char *filepath = DEFAULT_RET_STR;
	char *result_str = NULL;
	char *f_name = NULL;
	long long size;
	unsigned long ino;

	//分配内存给文件路径缓冲区
	pname_buf = kzalloc(PATH_MAX, GFP_KERNEL);
	if (unlikely(!pname_buf)) {
		return 0;
	}

	//只处理有效的文件删除操作
	if (unlikely(IS_ERR_OR_NULL(dentry) || !(dentry->d_inode) || !S_ISREG(dentry->d_inode->i_mode))){
		kfree(pname_buf);
		return 0;	
	}

	//获取文件路径
	filepath = dentry_path_raw(dentry, pname_buf, PATH_MAX);
	if (unlikely(IS_ERR(filepath))) {
		kfree(pname_buf);
		return 0;
	}

	// 只监控特定目录的文件操作
	if (strncmp(filepath, MONITOR_PATH, strlen(MONITOR_PATH)) != 0) {
		kfree(pname_buf);
		return 0;  // 如果文件路径不匹配，则直接返回
	}
	//获取文件大小
	size = dentry->d_inode->i_size;
	if (unlikely(size <= 0)){
		kfree(pname_buf);
		return 0;
	}
	//记录文件名和inode号
	f_name = (char *)dentry->d_name.name;
	ino = dentry->d_inode->i_ino;

	result_str = kzalloc(RESULT_LEN, GFP_KERNEL);
	if (likely(result_str)){
		snprintf(result_str, RESULT_LEN, "process_name:%s\tprocess_parent:%s\nfile_op: %s\tfile_name:%s\tfile_path:%s\tsize: %lld Bytes\ninode:%lu\taccess_time:%lld\t\n",
									current->comm, current->real_parent->comm, DELETE_OP, f_name, filepath, size, ino, ktime_get_real_seconds());
	}

	pr_info("%s", result_str);
	//释放内存资源
	kfree(pname_buf);
	if (likely(result_str))
		kfree(result_str);

	return 0;
}

static int open_handler_pre(struct kprobe *p, struct pt_regs *regs)
{
	struct file *file = (struct file *)regs_get_arg1(regs);
	char *pname_buf = NULL;
	char *filepath = DEFAULT_RET_STR;
	char *result_str = NULL;
	char *f_name = NULL;
	long long size;
	unsigned long ino;

	//只处理有效的文件打开操作
	if (unlikely(IS_ERR_OR_NULL(file) || !(file->f_inode) || !S_ISREG(file->f_inode->i_mode))){
		return 0;	
	}

	//分配内存给文件路径缓冲区
	pname_buf = kzalloc(PATH_MAX, GFP_KERNEL);
	if (unlikely(!pname_buf)) {
		return 0;
	}

	//获取文件路径
	filepath = dentry_path_raw(file->f_path.dentry, pname_buf, PATH_MAX);
	if (unlikely(IS_ERR(filepath))){
		kfree(pname_buf);
		return 0;
	}

	// 只监控特定目录的文件操作
	if (strncmp(filepath, MONITOR_PATH, strlen(MONITOR_PATH)) != 0){
		kfree(pname_buf);
		return 0;
	}

	//获取文件大小
	size = file->f_path.dentry->d_inode->i_size;
	if (unlikely(size <= 0)){
		kfree(pname_buf);
		return 0;
	}

	//记录文件名和inode号
	f_name = (char *)file->f_path.dentry->d_name.name;
	ino = file->f_inode->i_ino;

	result_str = kzalloc(RESULT_LEN, GFP_KERNEL);
	if (likely(result_str){
		snprintf(result_str, RESULT_LEN, "process_name:%s\tprocess_parent:%s\nfile_op: %s\tfile_name:%s\tfile_path:%s\tsize: %lld Bytes\ninode:%lu\taccess_time:%lld\n",
			current->comm, current->real_parent->comm, OPEN_OP, f_name, filepath, size, ino, ktime_get_real_seconds());
	}
	pr_info("%s", result_str);

	//释放内存资源
	kfree(pname_buf);
	if (likely(result_str))
		kfree(result_str);

	return 0;
}

/* kprobe post_handler: called after the probed instruction is executed */


/* For each probe you need to allocate a kprobe structure */
static struct kprobe write_kprobe = {
	.symbol_name	= "vfs_write",
	.pre_handler = write_handler_pre,
};

static struct kprobe read_kprobe = {
	.symbol_name	= "vfs_read",
	.pre_handler = read_handler_pre,
};

static struct kprobe security_rename_kprobe = {
	.symbol_name = "security_inode_rename",
	.pre_handler = rename_handler_pre,
};

static struct kprobe close_kprobe = {
	.symbol_name = "filp_close",
	.pre_handler = close_handler_pre,
};

static struct kprobe create_kprobe = {
	.symbol_name = "security_inode_create",
	.post_handler = create_handler_post,
};

static struct kprobe delete_kprobe = {
	.symbol_name = "security_inode_unlink",
	.pre_handler = delete_handler_pre,
};

static struct kprobe open_kprobe = {
	.symbol_name = "security_file_open",
	.pre_handler = open_handler_pre,
};


static int register_write_kprobe(void){
	int ret;
	ret = register_kprobe(&write_kprobe);

	return ret;
}

static void unregister_write_kprobe(void){
	unregister_kprobe(&write_kprobe);
}

static int register_read_kprobe(void){
	int ret;
	ret = register_kprobe(&read_kprobe);

	return ret;
}

static void unregister_read_kprobe(void){
	unregister_kprobe(&read_kprobe);
}

static int register_rename_kprobe(void){
	int ret;
	ret = register_kprobe(&security_rename_kprobe);

	return ret;
}

static void unregister_rename_kprobe(void){
	unregister_kprobe(&security_rename_kprobe);
}

static int register_clsoe_kprobe(void){
	int ret;
	ret = register_kprobe(&close_kprobe);

	return ret;
}

static void unregister_close_kprobe(void){
	unregister_kprobe(&close_kprobe);
}

static int register_create_kprobe(void){
	int ret;
	ret = register_kprobe(&create_kprobe);

	return ret;
}

static void unregister_create_kprobe(void){
	unregister_kprobe(&create_kprobe);
}

static int register_delete_kprobe(void){
	int ret;
	ret = register_kprobe(&delete_kprobe);

	return ret;
}

static void unregister_delete_kprobe(void){
	unregister_kprobe(&delete_kprobe);
}

static int register_open_kprobe(void){
	int ret;
	ret = register_kprobe(&open_kprobe);

	return ret;
}

static void unregister_open_kprobe(void){
	unregister_kprobe(&open_kprobe);
}

static int install_kprobe(void){
	int ret;
	ret = register_write_kprobe();
	if (ret < 0)
		pr_err("register_write_kprobe failed, returned %d\n", ret);
	
	ret = register_read_kprobe();
	if (ret < 0)
		pr_err("register_read_kprobe failed, returned %d\n", ret);

	ret = register_rename_kprobe();
	if (ret < 0)
		pr_err("register_rename_kprobe failed, returned %d\n", ret);
	
	ret = register_clsoe_kprobe();
	if (ret < 0)
		pr_err("register_close_kprobe failed, returned %d\n", ret);

	ret = register_create_kprobe();
	if (ret < 0)
		pr_err("register_create_kprobe failed, returned %d\n", ret);

	ret = register_delete_kprobe();
	if (ret < 0)
		pr_err("register_delete_kprobe failed, returned %d\n", ret);

	ret = register_open_kprobe();
	if (ret < 0)
		pr_err("register_open_kprobe failed, returned %d\n", ret);	

	return ret;
}

static void uninstall_kprobe(void){
	unregister_write_kprobe();
	unregister_read_kprobe();
	unregister_rename_kprobe();
	unregister_close_kprobe();
	unregister_create_kprobe();
	unregister_delete_kprobe();
	unregister_open_kprobe();
}

static int __init kprobe_init(void)
{
	int ret;

	// mutex_init(&kmutex);
	// rwlock_init(&write_lock);
	ret = install_kprobe();
	if (ret < 0) {
		pr_err("register_kprobe failed\n, returned %d\n", ret);
		return ret;
	}
	pr_info("register_ kprobe success: write/read/rename/close/create/delete.\n");
	return 0;
}

static void __exit kprobe_exit(void)
{
	uninstall_kprobe();
	// mutex_unlock(&kmutex);
	pr_info("kprobe unregistered\n");
}

module_init(kprobe_init)
module_exit(kprobe_exit)
MODULE_LICENSE("GPL");
