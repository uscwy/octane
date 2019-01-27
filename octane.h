#ifndef __OCTANE_H__
#define __OCTANE_H__

#define SUCC 0
#define FAIL 1

#define MAX_CONF_NUM 512
#define MAX_CONF_LEN 128
#define BUF_LEN 1600
#define MAX_ROUTERS 5
#define MAX_IDLE_TIME 15
struct config {
	char name[MAX_CONF_NUM][MAX_CONF_LEN+1];
	unsigned int val[MAX_CONF_NUM];
	int num; /*number of iterms*/
};
#define OP_HELLO	1
#define OP_PACKET	2
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
#pragma pack()
#define HDR_LEN (sizeof(struct packet))
#endif
