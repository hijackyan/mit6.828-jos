//reboot
#include <inc/lib.h>

void
umain(int argc, char **argv)
{
	char *buf;
	cprintf("The hijackyan's JOS will reboot in 5 seconds\n");
	int s = sys_time();
		cprintf("%d\n", 5-((sys_time()-s)/100));
	while( sys_time() - s < 100);
		cprintf("%d\n", 5-((sys_time()-s)/100));
	while( sys_time() - s < 200);
		cprintf("%d\n", 5-((sys_time()-s)/100));
	while( sys_time() - s < 300);
		cprintf("%d\n", 5-((sys_time()-s)/100));
	while( sys_time() - s < 400);
		cprintf("%d\n", 5-((sys_time()-s)/100));
	while( sys_time() - s < 500);
	sys_reboot();
}
