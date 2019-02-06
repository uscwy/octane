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

#include "octane.h"
#include "log.h"
#include "tun.h"

/*configuration*/
struct config conf;
int stage;
int num_routers;
int rid; /*router id*/
int sockfd, tunfd;
struct sockaddr_in addrs[MAX_ROUTERS];
char buf[BUF_LEN];

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

/*packet handler*/
void packet_input(char *p, int len, struct sockaddr_in *s) {
	struct ip *ip=(struct ip *)p;
	struct packet *pkg=(struct packet *)buf;
	struct icmp *icmp=(struct icmp *)(ip+1);
	char from[64],ipsrc[32];

	if(ip->ip_p!=IPPROTO_ICMP) return;

	if(s==NULL) strcpy(from,"tunnel");
	else sprintf(from,"port %d",ntohs(s->sin_port));
	
	strcpy(ipsrc, inet_ntoa(ip->ip_src));

	log_print("ICMP from %s, src: %s, dst: %s, type: %d\n",
		from, ipsrc, inet_ntoa(ip->ip_dst),
		icmp->icmp_type);
	
	if(rid!=0) {
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
	}
	
	if(rid==0 && s==NULL) {
		pkg->op=htonl(OP_PACKET);
		memcpy(pkg->data, p, len);
		sendto(sockfd, buf, HDR_LEN+len, 0,
				(struct sockaddr *)&addrs[1], sizeof(addrs[1]));
	}
	if(rid==0 && s!=NULL) {
		tun_write(tunfd,p,len);
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
	/*send hello to primary router*/
	if(rid > 0) {
		send_hello();
	}

	memset(&tv, 0, sizeof(tv));

	nfd = sockfd;
	if(tunfd > sockfd) nfd = tunfd;
	nfd = nfd + 1;

	do {
		FD_SET(sockfd, &fds);
		if(tunfd > 0) FD_SET(tunfd, &fds);
		tv.tv_sec = MAX_IDLE_TIME;
		tv.tv_usec = 0;

		ret = select(nfd, &fds, NULL, NULL, &tv);
	       	
		if(FD_ISSET(sockfd, &fds)) {
			handle_udp();
		}
		if(FD_ISSET(tunfd, &fds)) {
			handle_tun();
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

