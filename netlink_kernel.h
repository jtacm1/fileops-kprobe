/*
    File:    netlink_kernel.h
    Description:    netlink kernel.c header file
    Author:    <jt>
*/

#include <linux/module.h>
#include <linux/kernel.h>
#include <net/sock.h>
#include <linux/netlink.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/types.h>
#include <linux/sched.h>
#include <linux/rwlock.h>

#define NETLINK_USER 31

// char *msg = "Hello this message is from kernel.\n";
void send_msg_to_user(char *msg, int flag);
void netlink_recv_msg(struct sk_buff *skb);
int netlink_init(void);
void netlink_exit(void);
