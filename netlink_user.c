#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <unistd.h>
#include <sys/time.h>
#include <time.h>

#define NETLINK_USER 17
#define MAX_PAYLOAD 1024

int main(int argc, char **argv){
    struct sockaddr_nl src_addr, dest_addr;
    struct nlmsghdr *nlh = NULL;
    struct iovec iov;
    int sock_fd;
    struct msghdr msg;
    int ret1;
    int ret2;
    
    //创建netlink socket
    sock_fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_USER);
    if(sock_fd < 0){
        perror("socket creation failed.\n");
        return -1;
    }   

    //初始化源地址
    memset(&src_addr, 0, sizeof(src_addr));
    src_addr.nl_family = AF_NETLINK;
    src_addr.nl_pid = getpid();
    src_addr.nl_groups = 0;

    if (bind(sock_fd, (struct sockaddr *)&src_addr, sizeof(src_addr)) < 0){
        perror("bind failed.\n");
        close(sock_fd);
        return -2;
    }

    //设置目的地址
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.nl_family = AF_NETLINK;
    dest_addr.nl_pid = 0; // For Linux Kernel
    dest_addr.nl_groups = 0;

    //初始化nlh
    nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(MAX_PAYLOAD));
    if (!nlh){
        perror("malloc failed.\n");
        close(sock_fd);
        return -3;
    }
    memset(nlh, 0, sizeof(nlh));
    nlh->nlmsg_len = NLMSG_SPACE(MAX_PAYLOAD);
    nlh->nlmsg_pid = getpid();
    nlh->nlmsg_flags = 0;
    //设置消息内容，表示用户态向内核态发送自己的pid以表示注册
    strcpy((char *)NLMSG_DATA(nlh), "REGISTER");
    //配置iovec
    memset(&iov, 0, sizeof(struct iovec));
    iov.iov_base = (void *)nlh;
    iov.iov_len = nlh->nlmsg_len;
    memset(&msg, 0, sizeof(struct msghdr));
    msg.msg_name = (void *)&dest_addr;
    msg.msg_namelen = sizeof(dest_addr);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    //发送消息给内核
    // while (sendmsg(sock_fd, &msg, 0) < 0)
    // {
    //     printf("sendmsg failed.\n");
    //     // nanosleep((const struct timespec[]) {{0, 850000}}, NULL);
    // }
    ret1 = sendmsg(sock_fd, &msg, 0);
    if (ret1 < 0){
        perror("sendmsg failed.\n");
        close(sock_fd);
        free(nlh);
        return -4;
    }

    printf("User pid %d send msg to kernel.\n", getpid());

    //循环接收内核消息
    while(1){
        ret2 = recvmsg(sock_fd, &msg, 0);
        
        //处理接收到的消息
        printf("Received message payload: %s\n", (char *)NLMSG_DATA(nlh));
    }

    //关闭socket 并释放资源
    close(sock_fd);
    free(nlh);
    return 0;

}