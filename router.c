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
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <sys/timerfd.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include "octane.h"
#include "log.h"
#include "tun.h"

/*configuration*/
struct config conf;
int stage;
int num_routers;
int rid; /*router id*/
int sockfd, tunfd, rawsockfd, timerfd, tcpfd, udpfd;
struct sockaddr_in addrs[MAX_ROUTERS];
char buf[BUF_LEN];
struct in_addr srcip;
struct flow_entry flow_table[MAX_FLOW_ENTRY];
int entry_num;
struct timer *timer_queue;
struct in_addr  origin_addr;
int drop_after;
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
            stage < 0 || stage > 6) {
        fprintf(stderr,"invalid stage %u\n", stage);
        return FAIL;
    }
    if(stage > 4) {
        if(get_conf("drop_after", &drop_after) == FAIL 
                || drop_after <= 0 || drop_after > 0x00ffffff) {
            fprintf(stderr, "invalid drop_after %u\n", drop_after);
            return FAIL;
        }
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
uint32_t get_router_ip(int router_id) {
    uint32_t addr = inet_addr(SECOND_ROUTER_INT_IP);
    addr = ntohl(addr) + router_id - 1;
    return htonl(addr);
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
    if(timer_queue == t) {
        timer_queue = t->next;
        return;
    }
    if(t->next)
        t->next->prev = t->prev;
    if(t->prev)
        t->prev->next = t->next;
}
void timer_enqueue(struct timer *t, struct timer **head) {

    struct timespec now;

    clock_gettime(CLOCK_REALTIME, &now);
    t->tv = now;
    t->tv.tv_sec += TIMEOUT;
   
    struct itimerspec itm;
    memset(&itm, 0, sizeof(itm));
    itm.it_value = t->tv;
    timerfd_settime(timerfd, TFD_TIMER_ABSTIME, &itm, NULL);

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
void timer_recv_ack(int16_t seq) {
    struct timer *t = timer_queue;
    while(t != NULL) {
        struct packet *pkg = (struct packet *)t->packet;
        struct octane_control *ctl=(struct octane_control *)pkg->data;
        struct timer *next = t->next;
        if(ctl->seqno == htons(seq)) {
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
    //struct packet *pkg=(struct packet *)t->packet;
    //struct octane_control *ctl=(struct octane_control *)pkg->data;
    sendto(t->sockfd, t->packet, t->len, 0, 
            (struct sockaddr *)&(t->addr), sizeof(struct sockaddr));
    return t;
}

/*timer handler*/
void handle_timer() {
    uint64_t exp;
    struct timespec now;

    struct timer *timer = timer_queue;
    struct timer *next;
    //struct itimerspec itm;
    read(timerfd, &exp, sizeof(exp));

    while(timer != NULL) {
        if(time_compare(&timer->tv, &now)) {
            timer = timer->next;
            continue;
        }
        next = timer->next;

        timer_dequeue(timer);
        timer = timer_resend(timer);
        /*insert to queue*/
        if(timer) timer_enqueue(timer, &timer_queue);

        timer = next;
        if(timer == timer_queue) break;
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
    memcpy(t->packet, packet, len);
    timer_resend(t);
    timer_enqueue(t, &timer_queue);
}
void rule_send(struct flow_entry *f, int offset, int target_rid) {
    static uint16_t seqno = 1;
    char bf[sizeof(struct octane_control)+32];
    struct packet *pkg=(struct packet *)bf;
    struct octane_control *ctl=(struct octane_control *)pkg->data;
    struct sockaddr_in addr;

    addr = addrs[target_rid];

    pkg->op=htonl(OP_CONTROL);
    ctl->action = f->action;
    ctl->flags = 0;
    ctl->seqno = htons(seqno);
    ctl->source_ip = f->src;
    ctl->dest_ip = f->dst;
    ctl->source_port = f->sport;
    ctl->dest_port = f->dport;
    ctl->protocol = f->proto;
    ctl->port = htons(f->port);

    int len = HDR_LEN + sizeof(struct octane_control);
    timer_add(sockfd, pkg, len, &addr);
    seqno++;
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
    sprintf(str,"(%s, %d, %s, %d, %d) action %d port %d", src,
            ntohs(f->sport), dst, ntohs(f->dport), f->proto, (f->action), f->port);
    return str;
}
/*add rule to flow table, offset=0 from the beginning, offset=-1 from the last*/
void rule_install(struct flow_entry *f, int offset, int target_rid) { 
    int i,begin,end,step;

    if(target_rid != rid) {
        /*send rule to secondary router*/
        rule_send(f, offset, target_rid);
        return;
    }

    if(offset < 0) {
        begin = MAX_FLOW_ENTRY-1;
        end = -1;
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
    if(stage > 3) 
        log_print("router: %d, rule installed %s\n", rid, flow_to_str(f));

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

void print_flow_table() {
    printf("router id=%d\n", rid);
    for(int i=0;i<MAX_FLOW_ENTRY;i++) {
        if(flow_table[i].action != FLOW_ACT_UNUSED) 
            printf("%s\n", flow_to_str(&flow_table[i]));
    }
}
void add_default_rule() {
    struct flow_entry f;

    if(rid>0 && stage>3) {
        /*default rule of secondary router*/
        f.action = FLOW_ACT_DROP;
        f.src = 0xffffffff;
        f.dst = f.src;
        f.sport = 0xffff;
        f.dport = f.sport;
        f.proto = 0xff;
        f.port = 0xffff;
        rule_install(&f, -1, rid);
        return;
    } 
}
void swap_src_dst(struct flow_entry *f) {
    uint32_t tmpip = f->dst;
    uint16_t tmpport = f->dport;
    f->dst = f->src;
    f->src = tmpip;

    f->dport = f->sport;
    f->sport = tmpport;
}
void post_config_rule() {
    struct flow_entry f;


    f.proto = IPPROTO_ICMP;
    f.sport = 0xffff;
    f.dport = 0xffff;

    /*primary router set ipaddress to secondary router*/
    for(int i=1;i<MAX_ROUTERS;i++) {
        if(addrs[i].sin_port == 0) continue;

        f.src = 0xffffffff;
        f.dst = get_router_ip(i);
        f.action = FLOW_ACT_REPLY;
        f.port = ntohs(addrs[0].sin_port);
        rule_install(&f, 0, i);
        
        f.action = FLOW_ACT_FORWARD;
        f.port = ntohs(addrs[i].sin_port);
        rule_install(&f, 0, rid);
        swap_src_dst(&f);
        f.port = 0;
        rule_install(&f, 0, rid);
    }

    if(stage < 6) return;

    /*config HTTP rules*/
    f.action = FLOW_ACT_FORWARD;
    f.src = 0xffffffff;
    f.dst = 0xffffffff;
    f.proto = IPPROTO_TCP;
    f.dport = htons(80);
    f.sport = 0xffff;
    f.port = ntohs(addrs[1].sin_port);
    rule_install(&f, 0, 0);

    f.port = 0;
    rule_install(&f, 0, 1);

    swap_src_dst(&f);
    f.port = 0;
    rule_install(&f, 0, 0);

    f.port = ntohs(addrs[0].sin_port);
    rule_install(&f, 0, 1);
    
    if(stage < 7) {
        /*HTTPS*/
        f.dport = htons(443);
        f.sport = 0xffff;
        f.port = ntohs(addrs[2].sin_port);
        rule_install(&f, 0, 0);
    
        f.port = 0;
        rule_install(&f, 0, 2);

        swap_src_dst(&f);
        f.port = 0;
        rule_install(&f, 0, 0);

        f.port = ntohs(addrs[0].sin_port);
        rule_install(&f, 0, 2);
    }
    else {
        /*stage = 7*/
        f.dport = htons(443);
        f.sport = 0xffff;
        f.port = ntohs(addrs[1].sin_port);
        rule_install(&f, 0, 0);
        f.port = ntohs(addrs[2].sin_port);
        rule_install(&f, 0, 1);
        f.port = 0;
        rule_install(&f, 0, 2);

        swap_src_dst(&f);
        f.port = ntohs(addrs[1].sin_port);
        rule_install(&f, 0, 2);
        f.port = ntohs(addrs[0].sin_port);
        rule_install(&f, 0, 1);
        f.port = 0;
        rule_install(&f, 0, 0);

    }
    print_flow_table(); 

}
int internal_send(void *p, int len, uint16_t port) {
    char b[1600];
    struct packet *pkg=(struct packet *)b;
    struct sockaddr_in addr;

    memset(&addr, 0, sizeof(addr));
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    addr.sin_port = htons(port);

    pkg->op=htonl(OP_PACKET);
    memcpy(pkg->data, p, len);
    return sendto(sockfd, pkg, HDR_LEN+len, 0,
         (struct sockaddr *)&addr, sizeof(addr));
    
}
int rawsocket_send(void *p, int len) {
    struct ip *ip=(struct ip *)p;
    struct icmp *icmp=(struct icmp *)(ip+1);
    if(SUBNET(ip->ip_dst.s_addr) == SUBNET(get_router_ip(rid))) {
        struct in_addr tmp = ip->ip_dst;
        ip->ip_dst = ip->ip_src;
        ip->ip_src = tmp;
        icmp->icmp_type = ICMP_ECHOREPLY;
        icmp->icmp_cksum = 0;
        icmp->icmp_code = 0;
        icmp->icmp_cksum = checksum((char *)icmp, 64);
        /*send reply to primary*/
        return internal_send(p, len, ntohs(addrs[0].sin_port));
    }
    printf("raw send len=%d rid=%d, proto=%d\n",ip->ip_p,len,rid,rawsockfd);
    printf("%s\n", inet_ntoa(ip->ip_dst));
    struct iovec iov[1];
    iov[0].iov_base = icmp;
    iov[0].iov_len = len-sizeof(struct ip);
    /*srcip = ip->ip_src;*/
    struct msghdr msg;
    struct sockaddr_in inaddr;
    memset(&inaddr, 0, sizeof(inaddr));
    inaddr.sin_family = AF_INET;
    inaddr.sin_addr = ip->ip_dst;
    origin_addr = ip->ip_src;
    memset(&msg, 0, sizeof(msg));
    /*inaddr.sin_addr = ip->ip_dst;*/
    msg.msg_name = &inaddr;
    msg.msg_namelen = sizeof(inaddr);
    msg.msg_iov = &iov[0];
    msg.msg_iovlen = 1;
    /*send to raw socket*/
    int ret = 0;
    if(ip->ip_p == IPPROTO_ICMP) ret = sendmsg(rawsockfd, &msg, 0);
    else if(ip->ip_p == IPPROTO_TCP) ret = sendmsg(tcpfd, &msg, 0);
    else if(ip->ip_p == IPPROTO_UDP) ret = sendmsg(udpfd, &msg, 0);
    return ret;
}
void distribute_rule(struct flow_entry *f) {
    static uint32_t counter = 0;
    uint32_t router_ip = get_router_ip(rid);
    int internal_ip = 0;
    /*only primary router distribute rules to others*/
    if(rid > 0) return;
    int target_rid = 1;
    /*keep input parameter*/
    struct flow_entry entry = *f;

    if(SUBNET(f->dst) == SUBNET(router_ip)) {
        internal_ip = 1;
        if(stage >= 6 && f->dst == get_router_ip(2)) target_rid = 2;
    }

    if(stage == 6 && f->proto == IPPROTO_TCP) {
        /*stage 6 policy*/
        if(ntohs(f->dport) == 80) target_rid = 1;
        else if(ntohs(f->dport) == 443) target_rid = 2;
    }
    if(stage == 7 && f->proto == IPPROTO_TCP && ntohs(f->dport) == 443) {
        /*stage 7 policy, direct https to r1 and then r2*/
        f->port = ntohs(addrs[1].sin_port);
        rule_install(f, 0, 0); 
        f->port = ntohs(addrs[2].sin_port);
        rule_install(f, 0, 1);
        f->port = 0;
        rule_install(f, 0, 2);
        swap_src_dst(f);
        f->port = ntohs(addrs[1].sin_port);
        rule_install(f, 0, 2);
        f->port = ntohs(addrs[0].sin_port);
        rule_install(f, 0, 1);
        f->port = 0;
        rule_install(f, 0, 0);
        
        *f = entry;
        f->port = ntohs(addrs[1].sin_port);
        return;
    }
    f->port = ntohs(addrs[target_rid].sin_port); /*point to target router*/
    rule_install(f, 0, 0); /*install on primary*/

    f->port = 0; /*to rawsocket*/
    if(internal_ip == 1) {
        f->action = FLOW_ACT_REPLY;
        f->port = htons(addrs[0].sin_port);
    }
    /*drop after N*/
    counter++;
    if(stage > 4 && counter > drop_after) {
        f->action = FLOW_ACT_DROP;
        counter = 0;
    }
    /*install rule to secondary routers*/
    rule_install(f, 0, target_rid);

    swap_src_dst(f);
    f->action = FLOW_ACT_FORWARD;
    f->port = 0; /*to tun*/
    rule_install(f, 0, rid);

    f->port = ntohs(addrs[0].sin_port); /*point to primary router*/

    if(internal_ip == 0) {
        rule_install(f, 0, target_rid);
    }
    /*keep original action*/
    *f = entry;
    f->port = ntohs(addrs[target_rid].sin_port);
}
void log_packet(void *p, uint16_t port) {
    char from[16];
    char ipsrc[32];
    struct ip *ip=(struct ip *)p;
    struct icmp *icmp=(struct icmp *)(ip+1);
    struct tcphdr *tcp=(struct tcphdr *)(ip+1);
    struct udphdr *udp=(struct udphdr *)(ip+1);

    if(port == 0 && rid == 0) strcpy(from, "tunnel");
    else if(port == 0 && rid > 0) strcpy(from, "raw scok");
    else sprintf(from, "port %d", port);
    
    strcpy(ipsrc, inet_ntoa(ip->ip_src));
    if(ip->ip_p == IPPROTO_ICMP) {
        log_print("ICMP from %s, src: %s, dst: %s, type: %d\n",
            from, ipsrc, inet_ntoa(ip->ip_dst),
            icmp->icmp_type);
    }
    else if(ip->ip_p == IPPROTO_TCP) {
        log_print("TCP from %s, (%s, %hu, %s, %hu)\n",
            from, ipsrc, ntohs(tcp->th_sport), inet_ntoa(ip->ip_dst),
            ntohs(tcp->th_dport));
    }
    else if(ip->ip_p == IPPROTO_UDP) {
        log_print("UDP from %s, (%s, %hu, %s, %hu)\n",
            from, ipsrc, ntohs(udp->uh_sport), inet_ntoa(ip->ip_dst),
            ntohs(udp->uh_dport));
    }
    else {
        log_print("IP from %s, (%s, %s, %h)\n",
            from, ipsrc, inet_ntoa(ip->ip_dst), ip->ip_p);
    }
}
/*packet handler*/
void packet_input(char *p, int len, uint16_t port) {
    struct ip *ip=(struct ip *)p;
    struct icmp *icmp=(struct icmp *)(ip+1);
    struct tcphdr *tcp=(struct tcphdr *)(ip+1);
    struct udphdr *udp=(struct udphdr *)(ip+1);

    if(port>0) log_packet(p, port);

    if(stage == 3) {
        if(rid == 0) { 
            if(port == 0) internal_send(p, len, ntohs(addrs[1].sin_port));
            else tun_write(tunfd, p, len);
        }
        else {
            if(port == 0) internal_send(p, len, ntohs(addrs[0].sin_port));
            else rawsocket_send(p,len);
        }
        return;
    }    
    struct flow_entry f,*flow;
    f.src = ip->ip_src.s_addr;
    f.dst = ip->ip_dst.s_addr;
    f.proto = ip->ip_p;
    f.sport = 0xffff;
    f.dport = 0xffff;
    if(ip->ip_p == IPPROTO_TCP) {
        f.sport = tcp->th_sport;
        f.dport = tcp->th_dport;
    }
    if(ip->ip_p == IPPROTO_UDP) {
        f.sport = udp->uh_sport;
        f.dport = udp->uh_dport;
    }
    flow = find_flow_entry(&f);
    if(flow==NULL) {
        if(port==0) {
            /*packet from tun, install new rule*/
            f.action = FLOW_ACT_FORWARD;
            distribute_rule(&f);
            flow = &f;
        }
        
    }
    else {
        if(stage > 3) 
            log_print("router: %d, rule hit %s\n", rid, flow_to_str(flow));
    }
    if(flow == NULL) return;
    char ipsrc[32];
    strcpy(ipsrc, inet_ntoa(ip->ip_src));
    printf("%s->%s, act=%d, port=%d, rid=%d\n", 
                ipsrc, inet_ntoa(ip->ip_dst), flow->action, flow->port, rid);
    if(flow->action == FLOW_ACT_FORWARD) {
        if(flow->port == 0 && port!=flow->port) {
            if(rid==0) {
                tun_write(tunfd,p,len);
            }
            else rawsocket_send(p, len);
        }
        else if(port == flow->port) {
            /*prevent loopback*/
        }
        else internal_send(p, len, flow->port);
    }
    if(flow->action == FLOW_ACT_REPLY) {
        if(ip->ip_p!=IPPROTO_ICMP) return;
        struct in_addr tmp = ip->ip_src;

        ip->ip_src = ip->ip_dst;
        ip->ip_dst = tmp;
        icmp->icmp_type = ICMP_ECHOREPLY;
        icmp->icmp_cksum = 0;
        icmp->icmp_code = 0;
        icmp->icmp_cksum = (checksum((char *)icmp, 64));
        
        internal_send(p, len, (flow->port));
    }
}
void handle_tun() {
    struct packet *pkg = (struct packet *)buf;
    pkg->op = OP_PACKET;
    int len = tun_read(tunfd, pkg->data, BUF_LEN-HDR_LEN);
    if(len <= 0) return;
    log_packet(pkg->data, 0);
    packet_input(pkg->data, len, 0);
}

/*read from udp socket*/
void handle_internal() {
    static int counter = 0;
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
        /*secondary registration*/
        struct pkg_hello *p = (struct pkg_hello *)pkg->data;
        id = ntohl(p->rid);
        if(addrs[id].sin_port == 0) {
            memcpy(&addrs[id], &addr, sizeof(addr));
            log_print("router: %d, pid: %d, port: %d\n",
                id, ntohl(p->pid), ntohs(addrs[id].sin_port));
        }
        counter++;
        if(counter == num_routers) {
            /*post_config_rule();*/
        }
    }
    else if(op == OP_CLOSE) {
        router_close();
    }
    else if(op == OP_PACKET) {
        /*packet deliver*/
        packet_input(pkg->data, len-HDR_LEN, ntohs(addr.sin_port));
    }
    else if(op == OP_CONTROL) {
        /*flow table control*/
        struct flow_entry f;
        struct octane_control *ctl = (struct octane_control *)pkg->data;
        f.action = ctl->action;
        f.src = ctl->source_ip;
        f.dst = ctl->dest_ip;
        f.sport = ctl->source_port;
        f.dport = ctl->dest_port;
        f.proto = ctl->protocol;
        f.port = ntohs(ctl->port);

        if(ctl->flags == 0) {
            /*receive new rule from primary router*/
            rule_install(&f, 0, rid);
            ctl->flags = 1; /*send ack*/
            sendto(sockfd, pkg, len, 0, (struct sockaddr *)&addr, addrlen);
        } else {
            /*receive ack from secondary router*/
            timer_recv_ack(ntohs(ctl->seqno));
        }
    }
    return;

}
/*packet handler for raw socket*/
void handle_rawsocket(int rawfd) {
    struct packet *pkg = (struct packet *)buf;
    struct sockaddr_in addr;
    socklen_t addrlen = sizeof(addr);
    int len;
    struct ip *ip = (struct ip *)pkg->data;

    len = recvfrom(rawfd, pkg->data, BUF_LEN, MSG_DONTWAIT,
        (struct sockaddr *)&addr, &addrlen);
    printf("recv %d len %d\n", rawfd, len);
    if(len < sizeof(struct ip)) {
        return;
    }
    log_packet(pkg->data, 0);
    
    /*restore original address*/
    ip->ip_dst = origin_addr;
    ip->ip_sum = 0;
    ip->ip_sum = checksum((char *)ip, 20);
    /*icmp->icmp_cksum = 0;
    icmp->icmp_cksum = checksum((char *)icmp, 64);*/
    packet_input(pkg->data, len, 0);
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
    rawsockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    tcpfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    udpfd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);

    struct sockaddr_in addr;
    char ipaddr[32];

    memset(&addr, 0, sizeof(addr));
    strcpy(ipaddr, SECOND_ROUTER_EXT_IP);
    ipaddr[strlen(ipaddr)-1] += (rid-1);
    addr.sin_family = AF_INET;
    inet_aton(ipaddr, &addr.sin_addr);

    /*get interface ipaddress*/
    if(stage > 5) {
        struct ifreq ifr;
        char ifname[] = "eth0";
        ifname[strlen(ifname)-1] += rid;
        strcpy(ifr.ifr_name, ifname);
        int sofd = socket(AF_INET, SOCK_DGRAM, 0);
        ioctl(sofd, SIOCGIFADDR, &ifr);
        addr.sin_addr = ((struct sockaddr_in *)(&ifr.ifr_addr))->sin_addr;
	    printf("interface: %s rid=%d\n", inet_ntoa(addr.sin_addr),rid);
        close(sofd);
    }
    printf("fds %d,%d,%d\n", rawsockfd, tcpfd, udpfd);

    if(bind(rawsockfd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        fprintf(stderr,"bind %s error - %s\n", ipaddr, strerror(errno));
    }
    if(bind(udpfd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        fprintf(stderr,"bind %s error - %s\n", ipaddr, strerror(errno));
    }
    if(bind(tcpfd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        fprintf(stderr,"bind %s error - %s\n", ipaddr, strerror(errno));
    }
    return rawsockfd;
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
    if(stage>2 && rid > 0) {
        rawsockfd = raw_socket_bind();
    }
    timerfd = timerfd_create(CLOCK_REALTIME, 0);
    /*send hello to primary router*/
    if(rid > 0) {
        send_hello();
    }
    
    /*install default flow entry*/
    if(stage > 2) add_default_rule();

    memset(&tv, 0, sizeof(tv));

    nfd = sockfd;
    if(tunfd > nfd) nfd = tunfd;
    if(rawsockfd > nfd) nfd = rawsockfd;
    if(timerfd > nfd) nfd = timerfd;
    if(tcpfd > nfd) nfd = tcpfd;
    if(udpfd > nfd) nfd = udpfd;

    nfd = nfd + 1;

    do {
        FD_SET(sockfd, &fds);
        if(rawsockfd > 0) FD_SET(rawsockfd, &fds);
        if(tunfd > 0) FD_SET(tunfd, &fds);
        if(timerfd > 0) FD_SET(timerfd, &fds);
        if(udpfd > 0) FD_SET(udpfd, &fds);
        if(tcpfd > 0) FD_SET(tcpfd, &fds);

        tv.tv_sec = MAX_IDLE_TIME;
        tv.tv_usec = 0;

        ret = select(nfd, &fds, NULL, NULL, &tv);
               
        if(FD_ISSET(sockfd, &fds)) {
            handle_internal();
        }
        if(FD_ISSET(tunfd, &fds)) {
            handle_tun();
        }
        if(FD_ISSET(rawsockfd, &fds)) {
            handle_rawsocket(rawsockfd);
        }
        if(FD_ISSET(timerfd, &fds)) {
            handle_timer();
        }
        if(FD_ISSET(udpfd, &fds)) {
            handle_rawsocket(udpfd);
        }
        if(FD_ISSET(tcpfd, &fds)) {
            handle_rawsocket(tcpfd);
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
    printf("num_routers=%u stage=%u drop_after=%d\n",num_routers,stage,drop_after);
    log_init();
    udp_dynamic_bind();
    create_router();
    /*start primary router*/
    router_process();
    return 0;
}

