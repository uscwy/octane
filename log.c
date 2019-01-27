#include <stdio.h>
#include <stdarg.h>

extern int rid, stage;

FILE *logfp = NULL;

void log_init() {
	char fname[128];
	sprintf(fname, "stage%d.r%d.out", stage, rid);
	
	if(logfp != NULL) fclose(logfp);
	logfp = fopen(fname, "w");
}
void log_print(char *fmt, ...) {
	va_list ap;

	if(logfp == NULL) return;

	va_start(ap, fmt);
	vfprintf(logfp, fmt, ap);
	va_end(ap);
	fflush(logfp);
}

