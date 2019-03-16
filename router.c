#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <string.h>
#include <sys/select.h>
#include <sys/types.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <sys/timerfd.h>
#include "octane.h"
#include "log.h"
#include "tun.h"

/*configuration*/
struct config conf;
int stage;
int num_routers;
int rid; /*router id*/
int sockfd, tunfd, rawsockfd, timerfd;
struct sockaddr_in addrs[MAX_ROUTERS];
char buf[BUF_LEN];
struct in_addr srcip;
struct flow_entry flow_table[MAX_FLOW_ENTRY];
int entry_num;
struct timer *timer_queue;

/*read item from conf*/
int get_conf(const char *name, int *val) {
	int i;
	for(i=0;i<conf.num;i++) {
		if(strcmp(conf.name[i], name) == 0) {
			*val = conf.val[i];
			return SUCC;
		}
	}
	return FAIL;
}
/*add item to conf*/
int add_conf(const char *name, int val) {
        int v;
        if(get_conf(name,&v) == SUCC) return FAIL;
        strncpy(conf.name[conf.num], name, MAX_CONF_LEN);
        conf.val[conf.num] = val;
        conf.num++;
        return SUCC;
}

/*read configure file into conf*/
int read_config(const char *fn) {
    FILE *fp;
	unsigned int i, value;
	const int maxlen=512;
	char buf[maxlen+1];
	char name[maxlen+1];

        if((fp = fopen(fn,"r")) == NULL) {
                fprintf(stderr,"%s cannot be opened - %s\n",
                                fn, strerror(errno));
                return FAIL;
        }
        while(fgets(buf,maxlen, fp) != NULL) {
		int tmp;
		i=0;
		while(isspace(buf[i])!=0) i++;
		/*end of string*/
		if(i==maxlen) continue;
		/*skip comments*/
		if(buf[i] == '#' || buf[i] == '\0') continue;
		/*continue search space*/
		if(sscanf(&buf[i], "%s %d", name, &value) != 2) continue;
		if(get_conf(name, &tmp) == SUCC) {
			fprintf(stderr, "duplicate config item - %s\n", name);
			return FAIL;
		}
		add_conf(name, value);
	}
        return SUCC;
}
int check_conf() {
	if(get_conf("num_routers",&num_routers) == FAIL 
			|| num_routers < 0 || num_routers > 10) {
		fprintf(stderr,"invalid num_routers %u\n", num_routers);
		return FAIL;
	}
	if(get_conf("stage",&stage) == FAIL || 
			stage < 0 || stage > 2) {
		fprintf(stderr,"invalid stage %u\n", stage);
		return FAIL;
	}
	return SUCC;
}
void router_close() {
	log_print("router %d closed\n", rid);
	if(rid==0) {
		for(int i=1;i<=num_routers;i++) {
			struct packet *p=(struct packet *)buf;
			p->op = htonl(OP_CLOSE);
			sendto(sockfd, buf, HDR_LEN, 0, 
				(struct sockaddr *)&addrs[i], sizeof(addrs[i]));
		}
	}
	exit(EXIT_SUCCESS);
}
int udp_dynamic_bind() {
	struct sockaddr_in addr;
	socklen_t addrlen = sizeof(addr);
	memset(&addr, 0, sizeof(addr));
	
	if(sockfd > 0) close(sockfd);

	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	addr.sin_family = AF_INET;
	if(bind(sockfd, (struct sockaddr *)&addr, addrlen) != 0) {
		fprintf(stderr, "bind failed: %s\n", strerror(errno));
		return FAIL;
	}
	if(getsockname(sockfd, (struct sockaddr *)&addr, &addrlen) != 0) {
		fprintf(stderr, "getsockname: %s\n", strerror(errno));
		return FAIL;
	}
	memcpy(&addrs[rid], &addr, addrlen);
	if(rid == 0) {
		addrs[0].sin_addr.s_addr = inet_addr("127.0.0.1");
		log_print("primary port: %d\n", ntohs(addrs[0].sin_port));
	} 
	else {
		log_print("router: %d, pid: %d, port: %d\n",
				rid, getpid(),ntohs(addrs[rid].sin_port));
	}
	return SUCC;
}
unsigned short checksum(char *addr, short count)
{
       /* Compute Internet Checksum for "count" bytes
        *         beginning at location "addr".
        */
       register long sum = 0;

        while( count > 1 )  {
           /*  This is the inner loop */
               sum += *(unsigned short *) addr;
	       addr += 2;
               count -= 2;
       }

           /*  Add left-over byte, if any */
       if( count > 0 )
               sum += * (unsigned char *) addr;

           /*  Fold 32-bit sum to 16 bits */
       while (sum>>16)
           sum = (sum & 0xffff) + (sum >> 16);

       return (unsigned short) ~sum;
}
uint32_t get_router_internal_ip() {
    uint32_t addr = inet_addr(SECOND_ROUTER_INT_IP);
    addr = ntohl(addr) + rid - 1;
    return htonl(addr);
}
/*add rule to flow table, offset=0 from the beginning, offset=-1 from the last*/
void rule_install(struct flow_entry *f, int offset) { 
    int i,begin,end,step;

    if(offset < 0) {
        begin = MAX_FLOW_ENTRY;
        end = 0;
        step = -1;
    }
    else {
        begin = 0;
        end = MAX_FLOW_ENTRY;
        step = 1;
    }
    for(i=begin;i!=end;i=i+step) {
        if(flow_table[i].action == FLOW_ACT_UNUSED) {
            flow_table[i] = *f;
            break;
        }
    }
}
int is_flow_match(struct flow_entry *f1, struct flow_entry *f2) {
    if(f1->src != f2->src && f1->src != 0xffffffff)
        return 0;
    if(f1->dst != f2->dst && f1->dst != 0xffffffff)
        return 0;
    if(f1->sport != f2->sport && f1->sport != 0xffff)
        return 0;
    if(f1->dport != f2->dport && f1->dport != 0xffff)
        return 0;
    if(f1->proto != f2->proto && f1->proto != 0xffff)
        return 0;

    return 1;
}
struct flow_entry *find_flow_entry(struct flow_entry *f) {
    for(int i=0;i<MAX_FLOW_ENTRY;i++) {
        if(is_flow_match(&flow_table[i], f) == 1)
            return &flow_table[i];
    }
    return NULL;
}
char *flow_to_str(struct flow_entry *f) {
    static char str[256];
    char src[32];
    char dst[32];
    struct in_addr s,d;
    s.s_addr = f->src;
    d.s_addr = f->dst;
    strcpy(src,inet_ntoa(s));
    strcpy(dst,inet_ntoa(d));
    sprintf(str,"(%s, %d, %s, %d, %d) action %d", src,
            ntohs(f->sport), dst, ntohs(f->dport), f->proto, ntohs(f->action));
    return str;
}
void add_default_rule() {
    struct flow_entry f;
    f.action = FLOW_ACT_DROP;
    f.src = 0xffffffff;
    f.dst = f.src;
    f.sport = 0xffff;
    f.dport = f.sport;
    f.proto = 0xff;
    f.port = 0xffff;
    rule_install(&f, rid);
}
int rawsocket_send(void *p, long len) {
            struct iovec iov[1];
            iov[0].iov_base = p;
            iov[0].iov_len = len;
            /*srcip = ip->ip_src;*/
            struct msghdr msg;
            struct sockaddr_in inaddr;
            memset(&inaddr, 0, sizeof(inaddr));
            memset(&msg, 0, sizeof(msg));
            /*inaddr.sin_addr = ip->ip_dst;*/
            msg.msg_name = &inaddr;
            msg.msg_namelen = sizeof(inaddr);
            msg.msg_iov = &iov[0];
            msg.msg_iovlen = 1;
            /*send to raw socket*/
            return sendmsg(rawsockfd, &msg, 0);
}
/*packet handler*/
void packet_input(char *p, int len, struct sockaddr_in *s) {
	struct ip *ip=(struct ip *)p;
	struct packet *pkg=(struct packet *)buf;
	struct icmp *icmp=(struct icmp *)(ip+1);
	char from[64],ipsrc[32];


	if(s==NULL) strcpy(from,"tunnel");
	else sprintf(from,"port %d",ntohs(s->sin_port));
	

	if(ip->ip_p==IPPROTO_ICMP) {
	    strcpy(ipsrc, inet_ntoa(ip->ip_src));
	    log_print("ICMP from %s, src: %s, dst: %s, type: %d\n",
		    from, ipsrc, inet_ntoa(ip->ip_dst),
		    icmp->icmp_type);
    }
	
    struct flow_entry f,*flow;
    f.src = ip->ip_src.s_addr;
    f.dst = ip->ip_dst.s_addr;
    f.proto = ip->ip_p;
    f.sport = 0xffff;
    f.dport = 0xffff;
    if(ip->ip_p == IPPROTO_TCP) {
    }
    if(ip->ip_p == IPPROTO_UDP) {
    }
    flow = find_flow_entry(&f);
    if(flow==NULL) {
        if(rid == 0) {
            /*primary router*/
            f.action = FLOW_ACT_FORWARD;
            f.port = addrs[1].sin_port;
            rule_install(&f, 0);
        }
        log_print("router: %d, rule installed %s", rid, flow_to_str(&f));
    }
    else {
        log_print("router: %d, rule hit %s", rid, flow_to_str(&f));
    }
    if(f.action == FLOW_ACT_FORWARD) {
        if(f.port == 0) {
            if(rid == 0) tun_write(tunfd,p,len);
            else rawsocket_send(p, len);
        }
    }
	if(f.action == FLOW_ACT_REPLY) {
	    if(ip->ip_p!=IPPROTO_ICMP) return;
        struct in_addr tmp = ip->ip_src;

        ip->ip_src = ip->ip_dst;
        ip->ip_dst = tmp;
        icmp->icmp_type = ICMP_ECHOREPLY;
        icmp->icmp_cksum = 0;
        icmp->icmp_code = 0;
        icmp->icmp_cksum = (checksum((char *)icmp, 64));
        pkg->op=htonl(OP_PACKET);
        memcpy(pkg->data, p, len);
        sendto(sockfd, buf, HDR_LEN+len, 0,
                (struct sockaddr *)s, sizeof(*s));

		pkg->op=htonl(OP_PACKET);
		memcpy(pkg->data, p, len);
		sendto(sockfd, buf, HDR_LEN+len, 0,
				(struct sockaddr *)&addrs[1], sizeof(addrs[1]));
	}
}
void handle_tun() {
	struct packet *pkg = (struct packet *)buf;
	pkg->op = OP_PACKET;
	int len = tun_read(tunfd, pkg->data, BUF_LEN-HDR_LEN);
	if(len <= 0) return;
	packet_input(pkg->data, len, NULL);
	/*for(int i=1;i<=num_routers;i++) {
	        int r = sendto(sockfd, pkg, HDR_LEN+len, 0,
                                (struct sockaddr *)&addrs[i], sizeof(addrs[i]));
	        if(r<0) fprintf(stderr, "sendto failed %s\n", strerror(errno));
	}*/
}

/*read from udp socket*/
void handle_udp() {
	struct packet *pkg = (struct packet *)buf;
	unsigned int op, id;
	struct sockaddr_in addr;
	socklen_t addrlen = sizeof(addr);
	int len;
	
	len = recvfrom(sockfd, pkg, BUF_LEN, MSG_DONTWAIT,
		(struct sockaddr *)&addr, &addrlen);
	
	
	if(len < HDR_LEN) {
		return;
	}
	op = ntohl(pkg->op);
	if(op == OP_HELLO) {
		struct pkg_hello *p = (struct pkg_hello *)pkg->data;
		id = ntohl(p->rid);
		if(addrs[id].sin_port == 0) {
			memcpy(&addrs[id], &addr, sizeof(addr));
			log_print("router: %d, pid: %d, port: %d\n",
				id, ntohl(p->pid), ntohs(addrs[id].sin_port));
		}
	}
	else if(op == OP_CLOSE) {
		router_close();
	}
	else if(op == OP_PACKET) {
		packet_input(pkg->data, len-HDR_LEN, &addr);
	}
	return;

}
/*packet handler for raw socket*/
void handle_rawsocket() {
    struct packet *pkg = (struct packet *)buf;
    struct sockaddr_in addr;
    socklen_t addrlen = sizeof(addr);
    char src[32], dst[32];
    int len;
    struct ip *ip = (struct ip *)pkg->data;
	struct icmp *icmp=(struct icmp *)(ip+1);

    len = recvfrom(rawsockfd, pkg->data, BUF_LEN, MSG_DONTWAIT,
        (struct sockaddr *)&addr, &addrlen);


    if(len < sizeof(struct ip)) {
        return;
    }

	if(ip->ip_p!=IPPROTO_ICMP) return;

    strcpy(src, inet_ntoa(ip->ip_src));
    strcpy(dst, inet_ntoa(ip->ip_dst));

	log_print("ICMP from raw sock, src: %s, dst: %s, type: %d\n",
        src, dst, icmp->icmp_type);

    ip->ip_dst = srcip;
    icmp->icmp_cksum = (checksum((char *)icmp, 64));
    pkg->op=htonl(OP_PACKET);
    sendto(sockfd, buf, HDR_LEN+len, 0,
                (struct sockaddr *)&addrs[0], sizeof(addrs[0]));

}
void send_hello() {
	struct packet *hdr = (struct packet *)buf;
	struct pkg_hello *hello=(struct pkg_hello *)(hdr+1);
	hdr->op = htonl(OP_HELLO);
	hello->pid = htonl(getpid());
	hello->rid = htonl(rid);
	int len = HDR_LEN + sizeof(struct pkg_hello);
	sendto(sockfd, hdr, len, 0, 
			(struct sockaddr *)&addrs[0], sizeof(addrs[0]));

	/*fprintf(stderr,"rid=%d, sendto %s:%d\n",rid,
			inet_ntoa(addrs[0].sin_addr),
			htons(addrs[0].sin_port));*/

}
int raw_socket_bind() {
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    struct sockaddr_in addr;
    char ipaddr[32];

    memset(&addr, 0, sizeof(addr));
    strcpy(ipaddr, SECOND_ROUTER_EXT_IP);
    ipaddr[strlen(ipaddr)-1] += rid;
    addr.sin_family = AF_INET;
    inet_aton(ipaddr, &addr.sin_addr);

    if(bind(sock, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        fprintf(stderr,"bind %s error\n", ipaddr);
    }
    return sock;
}
/*return true if tv1 > tv2*/
int time_compare(struct timespec *tv1, struct timespec *tv2) {
    if(tv1->tv_sec > tv2->tv_sec) 
        return 1;
    if(tv1->tv_sec == tv2->tv_sec) {
        if(tv1->tv_nsec > tv2->tv_nsec)
            return 1;
    }
    return 0;
}
/**/
void timer_dequeue(struct timer *t) {
    if(t->next)
        t->next->prev = t->prev;
    if(t->prev)
        t->prev->next = t->next;
}
void timer_enqueue(struct timer *t, struct timer **head) {
    if(*head == NULL) {
        *head = t;
        t->prev = NULL;
        t->next = NULL;
        return;
    }
    struct timer *tmp = *head;
    while(tmp->next != NULL) {
        tmp = tmp->next;
    }
    tmp->next = t;
    t->prev = tmp;
    t->next = NULL;
}
void timer_free(struct timer *t) {
    free(t->packet);
    free(t);
}
void recv_ack(int32_t seq) {
    struct timer *t = timer_queue;
    while(t != NULL) {
        struct packet *pkg = (struct packet *)t->packet;
        struct octane_control *ctl=(struct octane_control *)pkg->data;
        struct timer *next = t->next;
        if(ctl->seqno == seq) {
            timer_dequeue(t);
            timer_free(t);
        }
        t = next;
    }
}
struct timer *timer_resend(struct timer *t) {
    if(t->resend > MAX_RESEND) {
        timer_free(t);
        return NULL;
    }
    t->resend++;
    t->tv.tv_sec += TIMEOUT;
    sendto(t->sockfd, t->packet, t->len, 0, 
            (struct sockaddr *)&t->addr, sizeof(struct sockaddr));
    return t;
}
/*timer handler*/
void handle_timer() {
    struct timespec now;
    clock_gettime(CLOCK_REALTIME, &now);

    struct timer *timer = timer_queue;
    struct timer *next;
    struct itimerspec itm;

    while(timer != NULL) {
        if(time_compare(&timer->tv, &now)) {
            memset(&itm, 0, sizeof(itm));
            itm.it_value = timer->tv;
            timerfd_settime(timerfd, TFD_TIMER_ABSTIME, &itm, NULL);
            return;
        }
        next = timer->next;

        timer_dequeue(timer);
        timer = timer_resend(timer);
        /*insert to queue*/
        if(timer) timer_enqueue(timer, &timer_queue);

        timer = next;
    }
}
void timer_add(int sockfd, void *packet, int len, struct sockaddr_in *addr) {
    void *p=malloc(len);
    struct timer *t = malloc(sizeof(struct timer));
    if(p==NULL || t==NULL) return;
    t->sockfd = sockfd;
    t->packet = p;
    t->len = len;
    t->addr = *addr;
    t->resend = 0;
    clock_gettime(CLOCK_REALTIME, &t->tv);
    memcpy(t->packet, packet, len);
    timer_resend(t);
    timer_enqueue(t, &timer_queue);
    handle_timer();
}
/*router process, never return*/
int router_process() {
	fd_set fds;
	struct timeval tv;
	int nfd = 0;
	char tun[32] = "tun1";
	int ret;

	FD_ZERO(&fds);
	/*open tun dev*/
	if(stage>1 && rid == 0) {
		tunfd = tun_alloc(tun);
	}
    if(stage>1 && rid > 0) {
        rawsockfd = raw_socket_bind();
    }
    timerfd = timerfd_create(CLOCK_REALTIME, 0);
	/*send hello to primary router*/
	if(rid > 0) {
		send_hello();
	}
    
    /*install default flow entry*/
    if(stage == 6) add_default_rule();

	memset(&tv, 0, sizeof(tv));

	nfd = sockfd;
	if(tunfd > nfd) nfd = tunfd;
    if(rawsockfd > nfd) nfd = rawsockfd;
    if(timerfd > nfd) nfd = timerfd;

	nfd = nfd + 1;

	do {
		FD_SET(sockfd, &fds);
        if(rawsockfd > 0) FD_SET(rawsockfd, &fds);
		if(tunfd > 0) FD_SET(tunfd, &fds);
        if(timerfd > 0) FD_SET(timerfd, &fds);

		tv.tv_sec = MAX_IDLE_TIME;
		tv.tv_usec = 0;

		ret = select(nfd, &fds, NULL, NULL, &tv);
	       	
		if(FD_ISSET(sockfd, &fds)) {
			handle_udp();
		}
		if(FD_ISSET(tunfd, &fds)) {
			handle_tun();
		}
        if(FD_ISSET(rawsockfd, &fds)) {
            handle_rawsocket();
        }
        if(FD_ISSET(timerfd, &fds)) {
            handle_timer();
        }
	} while(ret > 0 || rid > 0);

	router_close();
	return 0;
}
/*create other router instance*/
void create_router() {
	int id;
	for(id=1;id<=num_routers;id++) {
		if(fork() == 0) {
			rid = id;
			log_init();
			udp_dynamic_bind();
			router_process();
		}
	}
}

int main(int argc, char **argv) {
        if(argc != 2) {
                fprintf(stderr,"Usage: %s config_file\n", argv[0]);
                return 1;
        }
        if(read_config(argv[1]) != SUCC || check_conf() != SUCC) {
                return 1;
        }
        printf("num_routers=%u stage=%u\n",num_routers,stage);
	log_init();
	udp_dynamic_bind();
	create_router();
	/*start primary router*/
	router_process();
        return 0;
}

