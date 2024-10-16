//
// Created by jt on 2024/10/12.
//

#ifndef UTIL_H
#define UTIL_H
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/fs.h>

#define DEFAULT_RET_STR "-2"
#define NAME_TOO_LONG "-4"

// struct event_context {
//     char * process_name;	//进程名
//     char * process_parent; //父进程名
//     const char * access_op;	//访问操作
//     const unsigned char * file_name;     //文件名
//     char * file_path;     //文件路径
//     size_t size;  //文件大小
//     unsigned long inode;  //文件inode
//     s64 access_time; //访问时间
// } event_context;

#define f_kmalloc(size, flags) kmalloc(size, flags | __GFP_NOWARN)
#define f_kzalloc(size, flags) kzalloc(size, flags | __GFP_NOWARN)
#define f_kfree(ptr) while (0) { void * _ptr; if (_ptr) kfree(ptr);}


static __always_inline unsigned long __must_check f_copy_from_user(void *to, const void __user *from, unsigned long n)
{
    unsigned long res;
    preempt_disable();
    /* validate user-mode buffer: ['from' - 'from' + 'n') */
    if (access_ok(from, n))
        res = __copy_from_user_inatomic(to, from, n);
    else
        res = n;
    preempt_enable();
    return res;
}

static inline unsigned long regs_get_arg1(struct pt_regs *regs) {
    return regs->di;
}

static inline unsigned long regs_get_arg2(struct pt_regs *regs) {
    return regs->si;
}

static inline unsigned long regs_get_arg3(struct pt_regs *regs) {
    return regs->dx;
}

static inline unsigned long regs_get_arg4(struct pt_regs *regs) {
    return regs->cx;
}

static inline unsigned long regs_get_arg5(struct pt_regs *regs) {
    return regs->r8;
}

static inline unsigned long regs_get_arg6(struct pt_regs *regs) {
    return regs->r9;
}


static inline unsigned long regs_get_arg1_syscall(struct pt_regs *regs) {
    return regs->di;
}

static inline unsigned long regs_get_arg2_syscall(struct pt_regs *regs) {
    return regs->si;
}

static inline unsigned long regs_get_arg3_syscall(struct pt_regs *regs) {
    return regs->dx;
}

static inline unsigned long regs_get_arg4_syscall(struct pt_regs *regs) {
    return regs->r10;
}

static inline unsigned long regs_get_arg5_syscall(struct pt_regs *regs) {
    return regs->r8;
}

static inline unsigned long regs_get_arg6_syscall(struct pt_regs *regs) {
    return regs->r9;
}

// Only Syscall Functions Parameter Can Use get_arg()
static inline unsigned long get_arg1_syscall(struct pt_regs *regs) {
    return regs_get_arg1_syscall((struct pt_regs *)regs_get_arg1_syscall(regs));
}

static inline unsigned long get_arg2_syscall(struct pt_regs *regs) {
    return regs_get_arg2_syscall((struct pt_regs *)regs_get_arg1_syscall(regs));
}

static inline unsigned long get_arg3_syscall(struct pt_regs *regs) {
    return regs_get_arg3_syscall((struct pt_regs *)regs_get_arg1_syscall(regs));
}

static inline unsigned long get_arg4_syscall(struct pt_regs *regs) {
    return regs_get_arg4_syscall((struct pt_regs *)regs_get_arg1_syscall(regs));
}

static inline unsigned long get_arg5_syscall(struct pt_regs *regs) {
    return regs_get_arg5_syscall((struct pt_regs *)regs_get_arg1_syscall(regs));
}

static inline unsigned long get_arg6_syscall(struct pt_regs *regs) {
    return regs_get_arg6_syscall((struct pt_regs *)regs_get_arg1_syscall(regs));
}

#endif //UTIL_H
