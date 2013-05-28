//show the time
#include <inc/lib.h>

void
umain(int argc, char **argv)
{
	cprintf("Hello, user\n");
	int s = sys_time();
	cprintf("The system has run %d.%d seconds \n", s/100,s%100);
}
