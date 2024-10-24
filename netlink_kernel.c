#include "netlink_kernel.h"

// struct sock *nl_sk = NULL;
// rwlock_t nl_sk_lock;
//void netlink_recv_msg(struct sk_buff *skb);
//
//void send_msg_to_user(char *msg, int flag);

static int user_pid = 0;
static struct sock *nl_sk;
//内核态 接受netlink消息的回调函数
void netlink_recv_msg(struct sk_buff *skb)
{
    struct nlmsghdr *nlh;
    char *user_msg;

    //获取netlinkx消息头部
    nlh = nlmsg_hdr(skb);
    user_msg = (char *)nlmsg_data(nlh);
    if (user_msg){
        printk("netlink user message is : %s\n", user_msg);
        user_pid = nlh->nlmsg_pid;
        printk("user pid: %d registered\n", user_pid);
        send_msg_to_user("Hello, this is a kernel message send to user space.\n", 1);
    } else 
    {
        printk("No message received\n");
        return;
    }
    
    return ;

}

//内核态 向用户态发送消息
void send_msg_to_user(char *msg, int flag)
{
    struct sk_buff *skb;
    struct nlmsghdr *nlh;
    int msg_size = strlen(msg);
    int res;

    if (user_pid == 0)
    {
        printk("No user pid available\n");
        return;
    }
    //创建消息缓冲区
    skb = nlmsg_new(msg_size, GFP_KERNEL);    
    if (!skb) {
        printk("Failed to allocate new skb\n");
        return;
    }
    // write_lock(&nl_sk_lock);
    //填充netlink消息头
    nlh = nlmsg_put(skb, 0, 0, NLMSG_DONE, msg_size, 0);
    if (!nlh) {
        printk("Failed to put nl header\n");
        kfree_skb(skb);
        return;
    }
    strncpy(NLMSG_DATA(nlh), msg, msg_size);
    //发送消息到用户态
    res = nlmsg_unicast(nl_sk, skb, user_pid);
    // write_unlock(&nl_sk_lock);
    if (res < 0) {
        printk("Error in sending message to user\n");
    } else {
        printk("Message sent to user successfully, message:%s\n", msg);
    }

    // kfree(skb);
    if(flag)
        kfree(msg);
}



//内核态 注册netlink
int netlink_init(void)
{
    // int ret;
    struct netlink_kernel_cfg cfg = {
        .input = netlink_recv_msg,
    };
    //创建netlink套接字
    nl_sk = netlink_kernel_create(&init_net, NETLINK_GENERIC, &cfg);
    if (!nl_sk) {
        printk("Error creating socket.\n");
        return -10;
    }
    // rwlock_init(&nl_sk_lock);
    printk("Netlink socket created\n");
    // send_msg_to_user(msg);
    return 0;
}

//内核态 卸载netlink
void netlink_exit(void)
{
    netlink_kernel_release(nl_sk);
    printk("Socket released\n");
}
MODULE_LICENSE("GPL");