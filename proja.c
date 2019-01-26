#include <stdio.h>
#include <ctype.h>
#include <errno.h>
#include <string.h>

#include "octane.h"

/*configuration*/
struct config conf;

/*read configure file into conf*/
int read_config(const char *fn) {
        FILE *fp;
	unsigned int i, value;
	const int maxlen=512;
	char buf[maxlen+1];
	char name[maxlen+1];

	/*init conf*/
        conf.num_routers = 0;
        conf.stage = 0;

        if((fp = fopen(fn,"r")) == NULL) {
                fprintf(stderr,"%s cannot be opened - %s\n",
                                fn, strerror(errno));
                return 1;
        }
        while(fgets(buf,maxlen, fp) != NULL) {
		i=0;
		while(isspace(buf[i])!=0) i++;
		/*end of string*/
		if(i==maxlen) continue;
		/*skip comments*/
		if(buf[i] == '#' || buf[i] == '\0') continue;
		/*continue search space*/
		if(sscanf(&buf[i], "%s %u", name, &value) != 2) continue;
		if(strcmp("stage",name) == 0)
			conf.stage = value;
		else if(strcmp("num_routers",name)==0)
			conf.num_routers = value;
	}
	if(conf.num_routers == 0 || conf.num_routers > 10) {
		fprintf(stderr,"invalid num_routers %u\n", conf.num_routers);
		return 1;
	}
	if(conf.stage == 0 ||conf.stage > 2) {
		fprintf(stderr,"invalid stage %u\n", conf.stage);
		return 1;
	}
        return 0;
}
int main(int argc, char **argv) {
	if(argc != 2) {
		fprintf(stderr,"Usage: %s config_file\n", argv[0]);
		return 1;
	}
	if(read_config(argv[1]) != 0) {
		return 1;
	}
	fprintf(stderr,"num_routers=%u stage=%u\n",conf.num_routers,conf.stage);
}

