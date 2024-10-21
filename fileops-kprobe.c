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
#include <linux/string.h>
#include "./util.h"
#include <linux/list.h>
#include <linux/hashtable.h>


#define MONITOR_PATH "/home/jt/下载"  // 默认指定需要监控的目录
#define CREATE_OP "01"
#define OPEN_OP "02"
#define WRITE_OP "03"
#define READ_OP "04"
#define RENAME_OP "05"
#define CLOSE_OP "06"
#define DELETE_OP "07"

#define DEFAULT_INO -1
#define DEFAULT_SIZE 0

#define	RESULT_LEN	2048
// #define HASH_BITS 11
static char target_dir[PATH_MAX] = MONITOR_PATH;
module_param_string(dir, target_dir, PATH_MAX, 0644);
MODULE_PARM_DESC(dir, "target directory to monitor");
DEFINE_HASHTABLE(inode_hash_table, 11); //定义inode哈系表
LIST_HEAD(inode_list); //定义inode双向链表头
rwlock_t inode_hash_lock; //定义inode哈系表读写锁

//定义表中inode节点的结构体
struct inode_info {
	unsigned long ino; //inode号，文件唯一标识
	char *file_name; //文件名
	char *file_path; //文件路径
	long long size; //文件大小
	struct list_head i_list; //双向链表节点
	struct hlist_node i_hash; //哈系表节点
};

// static char *f_get_path(const struct file *file, char *buf, int buflen)
// {
// 	char *pathstr = DEFAULT_RET_STR;
// 	if (buf) {
// 		pathstr = d_path(&(file->f_path), buf, buflen);
// 		if (IS_ERR(pathstr))
// 			pathstr = NAME_TOO_LONG;
// 	}
// 	return pathstr;
// }

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


//获取task的进程执行文件路径
static char *get_exe_path(struct task_struct *task, char *buf, int size){
	char *exe_path = "-1";

	if (unlikely(!buf))
		return exe_path;

	if (likely(task->mm)){
		if(likely(task->mm->exe_file)){
			exe_path = d_path(&(task->mm->exe_file->f_path), buf, size);
		}
	}

	if (unlikely(IS_ERR(exe_path)))
		exe_path = "-1";

	return exe_path;

}

//获取当前进程的父进程的文件执行路径
static char *get_parent_exe_path(struct task_struct *task, char *buf, int size){
	char *exe_path = "-1";
	struct task_struct *p = NULL;

	if (task->real_parent){
		p = task->real_parent;
		exe_path = get_exe_path(p, buf, size);
	}

	return exe_path;
}

////添加某个inode项及对应的文件信息
static int add_inode(unsigned long ino, char *file_name, char *file_path, long long size){
	struct inode_info *i = NULL;
	//写入写锁
	write_lock(&inode_hash_lock);
	//分配内存空间
	i = kzalloc(sizeof(struct inode_info), GFP_KERNEL);
	if (!i){
		pr_alert("fail to alloc memory for inode_info.\n");
		write_unlock(&inode_hash_lock);
		return 0;
	}	
	//添加inode项
	i->ino = ino;
	i->file_name = kstrdup(file_name, GFP_KERNEL);
	i->file_path = kstrdup(file_path, GFP_KERNEL);
	if (!i->file_name || !i->file_path) {
		kfree(i->file_name);
		kfree(i->file_path);
		pr_alert("fail to alloc memory for file name or path.\n");
		kfree(i);
		write_unlock(&inode_hash_lock);
		return 0;
	}
	i->size = size;
	//添加到哈系表中
	hash_add(inode_hash_table, &(i->i_hash), ino);
	//添加到链表中
	list_add(&(i->i_list), &inode_list);
	//释放写锁
	write_unlock(&inode_hash_lock);
	pr_info("added inode: %lu, path: %s, file: %s\n", i->ino, i->file_path, i->file_name);
	return  1;
}

//查找某个inode项，获取对应的文件信息
static struct inode_info *find_inode(unsigned long ino)
{
	struct inode_info *i;

	//获取读锁
	read_lock(&inode_hash_lock);
	hash_for_each_possible(inode_hash_table, i, i_hash, ino)
	{
		if (i->ino == ino) {
			//释放读锁
			read_unlock(&inode_hash_lock);
			return i;
		}
	}
	// pr_info("inode: %lu not found.\n", ino);
	//没有找到匹配项，释放读锁
	read_unlock(&inode_hash_lock);
	return NULL;
}

static void delete_inode (unsigned long ino) {
	struct inode_info *i;
	//获取写锁
	write_lock(&inode_hash_lock);
	hash_for_each_possible(inode_hash_table, i, i_hash, ino)
	{
		if (i->ino == ino) {
			//从哈系表中删除
			hash_del(&i->i_hash);
			//从链表中删除
			list_del(&i->i_list);
			pr_info("deleted inode: %lu, path: %s. file: %s\n", i->ino, i->file_path, i->file_name);

			//释放内存
			kfree(i->file_name);
			kfree(i->file_path);
			kfree(i);
			//释放写锁
			write_unlock(&inode_hash_lock);
			return;
		}
	}
	pr_info("inode: %lu not found for deletion.\n", ino);
	//未找到匹配项，释放写锁
	write_unlock(&inode_hash_lock);
	return;
}

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
	char *exe_buf = NULL;
	char *exe_parent_buf = NULL;
	char *exe_path = NULL;
	char *exe_parent_path = NULL;
	struct inode_info *inode_info;
	struct inode *inode;
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

	inode = file_inode((const struct file *)file);
	if (unlikely(!inode))
	{
		kfree(pname_buf);
		return 0;
	}
	inode_info = find_inode(inode->i_ino);
	if (unlikely(!inode_info)){
		filepath = dentry_path_raw(file->f_path.dentry, pname_buf, PATH_MAX);
		if (unlikely(IS_ERR(filepath))) {
			kfree(pname_buf);
			return 0;
		}
		// 只监控特定目录的文件操作
		if (strncmp(filepath, target_dir, strlen(target_dir)) != 0) {
			kfree(pname_buf);
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
		ino = file->f_path.dentry->d_inode->i_ino;
		} else {
				filepath = inode_info->file_path;
				size = inode_info->size;
				if (unlikely(size <= 0)){
					kfree(pname_buf);
					return 0;
				}
				f_name = inode_info->file_name;
				ino = inode_info->ino;
		}	

	exe_buf = kzalloc(PATH_MAX, GFP_KERNEL);
	if (unlikely(!exe_buf)) {
		kfree(pname_buf);
		return 0;
	}
	exe_parent_buf = kzalloc(PATH_MAX, GFP_KERNEL);
	if (unlikely(!exe_parent_buf)){
		kfree(pname_buf);
		kfree(exe_buf);
		return 0;
	}
	//获取进程的执行路径和父进程的执行路径
	exe_path = get_exe_path(current, exe_buf, PATH_MAX);
	exe_parent_path = get_parent_exe_path(current, exe_parent_buf, PATH_MAX);

	result_str = kzalloc(RESULT_LEN, GFP_KERNEL);
	if (likely(result_str)){
		snprintf(result_str, RESULT_LEN, "task_name:%s\ttask_exe_path:%s\ttask_parent:%s\ttask_parent_exe_path:%s\nfile_op: %s\tfile_name:%s\tfile_path:%s\tsize: %lld Bytes\ninode:%lu\taccess_time:%lld\t\n",
				current->comm, exe_path, current->real_parent->comm, exe_parent_path, WRITE_OP, f_name, filepath, size, ino, ktime_get_real_seconds());
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
	kfree(exe_buf);
	kfree(exe_parent_buf);
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
	char *exe_buf = NULL;
	char *exe_parent_buf = NULL;
	char *exe_path = NULL;
	char *exe_parent_path = NULL;
	struct inode_info *inode_info;
	struct inode *inode;

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

	inode = file_inode((const struct file *)file);
	if (unlikely(!inode))
	{
		kfree(pname_buf);
		return 0;
	}
	inode_info = find_inode(inode->i_ino);
	if (unlikely(!inode_info)){
		filepath = dentry_path_raw(file->f_path.dentry, pname_buf, PATH_MAX);
		if (unlikely(IS_ERR(filepath))) {
			kfree(pname_buf);
			return 0;
		}
		// 只监控特定目录的文件操作
		if (strncmp(filepath, target_dir, strlen(target_dir)) != 0) {
			kfree(pname_buf);
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
		ino = file->f_path.dentry->d_inode->i_ino;
		} else {
				filepath = inode_info->file_path;
				size = inode_info->size;
				if (unlikely(size <= 0)){
					kfree(pname_buf);
					return 0;
				}
				f_name = inode_info->file_name;
				ino = inode_info->ino;
			}	

	exe_buf = kzalloc(PATH_MAX, GFP_KERNEL);
	if (unlikely(!exe_buf)) {
		kfree(pname_buf);
		return 0;
	}
	exe_parent_buf = kzalloc(PATH_MAX, GFP_KERNEL);
	if (unlikely(!exe_parent_buf)){
		kfree(pname_buf);
		kfree(exe_buf);
		return 0;
	}
	//获取进程的执行路径和父进程的执行路径
	exe_path = get_exe_path(current, exe_buf, PATH_MAX);
	exe_parent_path = get_parent_exe_path(current, exe_parent_buf, PATH_MAX);

	result_str = kzalloc(RESULT_LEN, GFP_KERNEL);
	if (likely(result_str)){
		snprintf(result_str, RESULT_LEN, "task_name:%s\ttask_exe_path:%s\ttask_parent:%s\ttask_paren_exe_path:%s\nfile_op: %s\tfile_name:%s\tfile_path:%s\tsize: %lld Bytes\ninode:%lu\taccess_time:%lld\t\n",
				current->comm, exe_path, current->real_parent->comm, exe_parent_path, READ_OP, f_name, filepath, size, ino, ktime_get_real_seconds());
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
    kfree(exe_buf);
	kfree(exe_parent_buf);

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
	char *exe_buf = NULL;
	char *exe_parent_buf = NULL;
	char *exe_path = NULL;
	char *exe_parent_path = NULL;
	struct inode_info *inode_info;

	if (unlikely(!old_dentry || !(old_dentry->d_inode) || !S_ISREG(old_dentry->d_inode->i_mode)))
		return 0;
	else 
		old_inode = old_dentry->d_inode;
	//分配路径缓冲区
	pname_buf = kzalloc(PATH_MAX, GFP_KERNEL);
	if (unlikely(!pname_buf)) {
		return 0;
	}

	//从哈希表中获取对应的文件信息
	inode_info = find_inode(old_inode->i_ino);
	if (unlikely(!inode_info)){
		filepath = dentry_path_raw(old_dentry, pname_buf, PATH_MAX);
		if (unlikely(IS_ERR(filepath))) {
			kfree(pname_buf);
			return 0;
		}

		// 只监控特定目录的文件操作
		if (strncmp(filepath, target_dir, strlen(target_dir)) != 0) {
			kfree(pname_buf);
			return 0;  // 如果文件路径不匹配，则直接返回
		}
		//获取文件大小
		size = old_dentry->d_inode->i_size;
		if (unlikely(size <= 0)){
			kfree(pname_buf);
			return 0;
		}
		//记录原文件名和inode号
		old_name = (char *)old_dentry->d_name.name;
		ino = old_dentry->d_inode->i_ino;
		} else {
				filepath = inode_info->file_path;
				size = inode_info->size;
				if (unlikely(size <= 0)){
					kfree(pname_buf);
					return 0;
				}
				old_name = inode_info->file_name;
				ino = inode_info->ino;
			}	

	//获取新文件名
	if (unlikely(!new_dentry || !(new_dentry->d_inode) || !S_ISREG(new_dentry->d_inode->i_mode)))
	{
		kfree(pname_buf);
		return 0;
	}
	new_name = (char *)new_dentry->d_name.name;

	exe_buf = kzalloc(PATH_MAX, GFP_KERNEL);
	if (unlikely(!exe_buf)) {
		kfree(pname_buf);
		return 0;
	}
	exe_parent_buf = kzalloc(PATH_MAX, GFP_KERNEL);
	if (unlikely(!exe_parent_buf)){
		kfree(pname_buf);
		kfree(exe_buf);
		return 0;
	}
	//获取进程的执行路径和父进程的执行路径
	exe_path = get_exe_path(current, exe_buf, PATH_MAX);
	exe_parent_path = get_parent_exe_path(current, exe_parent_buf, PATH_MAX);

	result_str = kzalloc(RESULT_LEN, GFP_KERNEL);
	if (likely(result_str)){
		snprintf(result_str, RESULT_LEN, "task_name:%s\ttask_exe_path:%s\ttask_parent:%s\ttask_paren_exe_path:%s\nfile_op: %s\tfile_name:%s\tfile_path:%s\tsize: %lld Bytes\ninode:%lu\taccess_time:%lld\t\n",
				current->comm, exe_path, current->real_parent->comm, exe_parent_path, READ_OP, f_name, filepath, size, ino, ktime_get_real_seconds());
	}

	pr_info("%s",result_str);
    // 释放资源
    kfree(pname_buf);
	if (likely(result_str))
		kfree(result_str);
    // write_unlock(&write_lock);
	kfree(exe_buf);
	kfree(exe_parent_buf);
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
	struct inode *inode;
	char *exe_buf = NULL;
	char *exe_parent_buf = NULL;
	char *exe_path = NULL;
	char *exe_parent_path = NULL;
	struct inode_info *inode_info;
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

	//从哈希表中获取对应的文件信息
	inode = file_inode((const struct file *)file);
	if (unlikely(!inode))
	{
		kfree(pname_buf);
		return 0;
	}
	inode_info = find_inode(inode->i_ino);
	if (unlikely(!inode_info)){
		filepath = dentry_path_raw(file->f_path.dentry, pname_buf, PATH_MAX);
		if (unlikely(IS_ERR(filepath))) {
			kfree(pname_buf);
			return 0;
		}
		// 只监控特定目录的文件操作
		if (strncmp(filepath, target_dir, strlen(target_dir)) != 0) {
			kfree(pname_buf);
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
		ino = file->f_path.dentry->d_inode->i_ino;
		} else {
				filepath = inode_info->file_path;
				size = inode_info->size;
				if (unlikely(size <= 0)){
					kfree(pname_buf);
					return 0;
				}
				f_name = inode_info->file_name;
				ino = inode_info->ino;
			}	
	exe_buf = kzalloc(PATH_MAX, GFP_KERNEL);
	if (unlikely(!exe_buf)) {
		kfree(pname_buf);
		return 0;
	}
	exe_parent_buf = kzalloc(PATH_MAX, GFP_KERNEL);
	if (unlikely(!exe_parent_buf)){
		kfree(pname_buf);
		kfree(exe_buf);
		return 0;
	}
	//获取进程的执行路径和父进程的执行路径
	exe_path = get_exe_path(current, exe_buf, PATH_MAX);
	exe_parent_path = get_parent_exe_path(current, exe_parent_buf, PATH_MAX);

	result_str = kzalloc(RESULT_LEN, GFP_KERNEL);
	if (likely(result_str)){
		snprintf(result_str, RESULT_LEN, "task_name:%s\ttask_exe_path:%s\ttask_parent:%s\ttask_paren_exe_path:%s\nfile_op: %s\tfile_name:%s\tfile_path:%s\tsize: %lld Bytes\ninode:%lu\taccess_time:%lld\t\n",
				current->comm, exe_path, current->real_parent->comm, exe_parent_path, READ_OP, f_name, filepath, size, ino, ktime_get_real_seconds());
	}
	pr_info("%s", result_str);
	delete_inode(ino);
	kfree(pname_buf);
	if (likely(result_str))
		kfree(result_str);
	kfree(exe_buf);
	kfree(exe_parent_buf);
	return 0;
}

static void create_handler_post(struct kprobe *p, struct pt_regs *regs, unsigned long flags){
	
	struct dentry *dentry = (struct dentry *)regs_get_arg2(regs);
	char *pname_buf = NULL;
	char *filepath = DEFAULT_RET_STR;
	char *result_str = NULL;
	char *f_name = NULL;
	char *exe_buf = NULL;
	char *exe_parent_buf = NULL;
	char *exe_path = NULL;
	char *exe_parent_path = NULL;
	// long long size;
	// long ino = DEFAULT_INO; 

	//分配内存给文件路径缓冲区
	pname_buf = kzalloc(PATH_MAX, GFP_KERNEL);
	if (unlikely(!pname_buf)) {
		return ;
	}

		//只处理有效的文件创建操作
	if (unlikely(IS_ERR_OR_NULL(dentry))){
		kfree(pname_buf);
		return ;	
	}
	//获取文件路径
	filepath = dentry_path_raw(dentry, pname_buf, PATH_MAX);
	if (unlikely(IS_ERR(filepath))) {
		kfree(pname_buf);
		return ;
	}
	// pr_info("%s\n", filepath);
	// 只监控特定目录的文件操作
	if (strncmp(filepath, target_dir, strlen(target_dir)) != 0) {
		kfree(pname_buf);
		return ;  // 如果文件路径不匹配，则直接返回
	}
	//记录文件名
	f_name = (char *)dentry->d_name.name;
	
	exe_buf = kzalloc(PATH_MAX, GFP_KERNEL);
	if (unlikely(!exe_buf)) {
		kfree(pname_buf);
		return 0;
	}
	exe_parent_buf = kzalloc(PATH_MAX, GFP_KERNEL);
	if (unlikely(!exe_parent_buf)){
		kfree(pname_buf);
		kfree(exe_buf);
		return 0;
	}
	//获取进程的执行路径和父进程的执行路径
	exe_path = get_exe_path(current, exe_buf, PATH_MAX);
	exe_parent_path = get_parent_exe_path(current, exe_parent_buf, PATH_MAX);

	result_str = kzalloc(RESULT_LEN, GFP_KERNEL);
	if (likely(result_str)){
		snprintf(result_str, RESULT_LEN, "task_name:%s\ttask_exe_path:%s\ttask_parent:%s\ttask_paren_exe_path:%s\nfile_op: %s\tfile_name:%s\tfile_path:%s\tsize: %lld Bytes\ninode:%lu\taccess_time:%lld\t\n",
				current->comm, exe_path, current->real_parent->comm, exe_parent_path, READ_OP, f_name, filepath, size, ino, ktime_get_real_seconds());
	}
	pr_info("%s", result_str);
	//释放内存资源
	// pr_info("是不是你5！\n");
	kfree(pname_buf);
	if (likely(result_str))
		kfree(result_str);
	kfree(exe_buf);
	kfree(exe_parent_buf);
	return ;
}

static int delete_handler_pre(struct kprobe *p, struct pt_regs *regs){
	struct dentry *dentry = (struct dentry *)regs_get_arg2(regs);
	char *pname_buf = NULL;
	char *filepath = DEFAULT_RET_STR;
	char *result_str = NULL;
	char *f_name = NULL;
	long long size;
	unsigned long ino;
	char *exe_buf = NULL;
	char *exe_parent_buf = NULL;
	char *exe_path = NULL;
	char *exe_parent_path = NULL;
	struct inode_info *inode_info = NULL;

	//分配内存给文件路径缓冲区
	pname_buf = kzalloc(PATH_MAX, GFP_KERNEL);
	if (unlikely(!pname_buf)) {
		return 0;
	}

	//只处理有效的文件删除操作
	//|| !S_ISREG(dentry->d_inode->i_mode)
	if (unlikely(IS_ERR_OR_NULL(dentry) || !(dentry->d_inode))){
		kfree(pname_buf);
		return 0;	
	}

	//从哈希表中获取对应的文件信息
	inode_info = find_inode(dentry->d_inode->i_ino);
	if (unlikely(!inode_info)){
		filepath = dentry_path_raw(dentry, pname_buf, PATH_MAX);
		if (unlikely(IS_ERR(filepath))) {
			kfree(pname_buf);
			return 0;
		}

		// 只监控特定目录的文件操作
		if (strncmp(filepath, target_dir, strlen(target_dir)) != 0) {
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
		} else {
				filepath = inode_info->file_path;
				size = inode_info->size;
				if (unlikely(size <= 0)){
					kfree(pname_buf);
					return 0;
				}
				f_name = inode_info->file_name;
				ino = inode_info->ino;
	}	
	exe_buf = kzalloc(PATH_MAX, GFP_KERNEL);
	if (unlikely(!exe_buf)) {
		kfree(pname_buf);
		return 0;
	}
	exe_parent_buf = kzalloc(PATH_MAX, GFP_KERNEL);
	if (unlikely(!exe_parent_buf)){
		kfree(pname_buf);
		kfree(exe_buf);
		return 0;
	}
	//获取进程的执行路径和父进程的执行路径
	exe_path = get_exe_path(current, exe_buf, PATH_MAX);
	exe_parent_path = get_parent_exe_path(current, exe_parent_buf, PATH_MAX);

	result_str = kzalloc(RESULT_LEN, GFP_KERNEL);
	if (likely(result_str)){
		snprintf(result_str, RESULT_LEN, "task_name:%s\ttask_exe_path:%s\ttask_parent:%s\ttask_paren_exe_path:%s\nfile_op: %s\tfile_name:%s\tfile_path:%s\tsize: %lld Bytes\ninode:%lu\taccess_time:%lld\t\n",
				current->comm, exe_path, current->real_parent->comm, exe_parent_path, READ_OP, f_name, filepath, size, ino, ktime_get_real_seconds());
	}

	pr_info("%s", result_str);

	//删除掉哈系表对应的文件信息
	delete_inode(ino);

	//释放内存资源
	kfree(pname_buf);
	if (likely(result_str))
		kfree(result_str);
	kfree(exe_buf);
	kfree(exe_parent_buf);
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
	char *exe_buf = NULL;
	char *exe_parent_buf = NULL;
	char *exe_path = NULL;
	char *exe_parent_path = NULL;
	int retval;

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
	if (strncmp(filepath, target_dir, strlen(target_dir)) != 0){
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

	//分配并将文件信息填充到inode_info中
	retval = add_inode(ino, f_name, filepath, size);
	if (!retval)
	{
		pr_info("add inode info failed\n");
		kfree(pname_buf);
		return 0;
	}

	exe_buf = kzalloc(PATH_MAX, GFP_KERNEL);
	if (unlikely(!exe_buf)) {
		kfree(pname_buf);
		return 0;
	}
	exe_parent_buf = kzalloc(PATH_MAX, GFP_KERNEL);
	if (unlikely(!exe_parent_buf)){
		kfree(pname_buf);
		kfree(exe_buf);
		return 0;
	}
	//获取进程的执行路径和父进程的执行路径
	exe_path = get_exe_path(current, exe_buf, PATH_MAX);
	exe_parent_path = get_parent_exe_path(current, exe_parent_buf, PATH_MAX);

	result_str = kzalloc(RESULT_LEN, GFP_KERNEL);
	if (likely(result_str)){
		snprintf(result_str, RESULT_LEN, "task_name:%s\ttask_exe_path:%s\ttask_parent:%s\ttask_paren_exe_path:%s\nfile_op: %s\tfile_name:%s\tfile_path:%s\tsize: %lld Bytes\ninode:%lu\taccess_time:%lld\t\n",
				current->comm, exe_path, current->real_parent->comm, exe_parent_path, READ_OP, f_name, filepath, size, ino, ktime_get_real_seconds());
	}
	pr_info("%s", result_str);

	//释放内存资源
	kfree(pname_buf);
	if (likely(result_str))
		kfree(result_str);
	kfree(exe_buf);
	kfree(exe_parent_buf);
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
	.symbol_name = "ext4_create",
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
	pr_info("register_ kprobe success: create/open/write/read/rename/close/delete_kprobe.\n");
	rwlock_init(&inode_hash_lock);
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
