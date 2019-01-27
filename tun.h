#ifndef __TUN_H_
#define __TUN_H__
extern int tun_alloc(char *);
extern int tun_read(int, char *, int);
extern int tun_write(int, char *, int);
#endif
