#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

int main(void) {
	setuid(1001);

	if (getuid() != 0) {
		fprintf(stderr,
		    "elevate: failed to elevate\n");
		return (1);
	}

	// if root access, we can pop a shell
	execl("/bin/sh", "/bin/sh", "-i", (char *)NULL);

	perror("execl");
	return 1;
}
