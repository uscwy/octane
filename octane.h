#ifndef __OCTANE_H__
#define __OCTANE_H__

#define SUCC 0
#define FAIL 1

#define MAX_CONF_NUM 512
#define MAX_CONF_LEN 128
#define BUF_LEN 3200
#define MAX_ROUTERS 10
#define MAX_IDLE_TIME 15
#define SECOND_ROUTER_EXT_IP "192.168.201.2"
#define SECOND_ROUTER_INT_IP "10.5.51.11"
#define MAX_RESEND 10
#define TIMEOUT 5
#define SUBNET(x)   (ntohl(x) & 0xffffff00)
struct config {
	char name[MAX_CONF_NUM][MAX_CONF_LEN+1];
	unsigned int val[MAX_CONF_NUM];
	int num; /*number of iterms*/
};
struct timer {
    struct timespec tv;
    int sockfd;
    int resend;
    void *packet;
    long len;
    struct sockaddr_in addr;
    struct timer *prev;
    struct timer *next;
};
struct pseudoheader {
    uint32_t src;
    uint32_t dst;
    uint8_t zero;
    uint8_t proto;
    uint16_t len;
};
#define OP_HELLO	1
#define OP_PACKET	2
#define OP_CONTROL  3
#define OP_CLOSE	255

#pragma pack(1)
struct packet {
	uint32_t op;
	char data[0];
};
struct pkg_hello {
	uint32_t rid;
	uint32_t pid;
};
struct octane_control {
    uint8_t action;
    uint8_t flags;
    uint16_t seqno;
    uint32_t source_ip;
    uint32_t dest_ip;
    uint16_t source_port;
    uint16_t dest_port;
    uint16_t protocol;
    uint16_t port;
};
#pragma pack()
struct flow_entry {
    uint32_t src;
    uint32_t dst;
    uint16_t dport;
    uint16_t sport;
    uint16_t proto;
    uint16_t port;
    uint8_t action;
};
#define FLOW_ACT_UNUSED     0
#define FLOW_ACT_FORWARD    1
#define FLOW_ACT_REPLY      2
#define FLOW_ACT_DROP       3
#define FLOW_ACT_REMOVE     4

#define MAX_FLOW_ENTRY 128
#define HDR_LEN (sizeof(struct packet))
#endif
