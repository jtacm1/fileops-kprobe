/*
    File:    share_mem.h
    Description:    Shared memory header file
    Author:    <jt>
*/

#include <linux/mm.h>
#include <linux/fs.h>
#include <linux/device.h>
#include <linux/module.h>
#include <linux/slab.h>

#define DVICE_NAME    "jt"
#define CLASS_NAME    "jt"

#define MAX_SIZE    4194304
#define BOUNDARY    4173824
#define READ_THRESHOLD    2097152

#define KERNEL_PRINT    0

extern int share_mem_flag;

struct msg_slot {
    int len;
    int next;
};

struct share_mem_list_head {
    int read_index;
    int next;
};

int init_share_mem(void);
int send_msg_2_user(char *msg, int kfree_flag);
void uninstall_share_mem(void);
