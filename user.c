#define _GNU_SOURCE
#include <linux/netlink.h>
#include <sys/socket.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>

#define NETLINK_RKCD 31
#define NETLINK_RKCD_GROUP 1

#define TASK_COMM_LEN 16
#define PATH_MAX 4096

enum log_type {
	LOG_SOCKET,
	LOG_FILE,
	LOG_PROCESS
};

struct log_entry {
	ulong id;
	enum log_type log_type;
	struct {
		/* must be filled for all */
		pid_t pid;
		pid_t tgid;
		char comm[TASK_COMM_LEN];
	} common;
	struct {
		/* filled only for LOG_SOCKET */
		struct sockaddr_storage saddr;
	} socket;
	struct {
		/* filled only for LOG_FILE */
		char filename[PATH_MAX + 1];
	} file;
};


void process_event(struct log_entry *event)
{
	FILE *file;
	char cmdbuf[128];
	char *cmd;
	/* printf("Kernel message: %i %s\n", result, event->file.filename); // print to android logs */
	static unsigned long j = 0;

	switch (event->log_type) {
		case LOG_PROCESS:
			asprintf(&cmd, "ps -eo pid | grep '^[[:blank:]]*%i$'",
					event->common.pid);
			file = popen(cmd, "r");
			fgets(cmdbuf, 128, file);
			if (atoi(cmdbuf) != event->common.pid)
				printf("Hidden pid %i: %s\n",
					event->common.pid, event->common.comm);
			pclose(file);
			free(cmd);
			break;
		case LOG_FILE:
			break;
		case LOG_SOCKET:
			break;
	}
	free(event);
	j++;
	if (!(j % 100))
		printf("DONE %lu\n", j);
}

void *__process_event(void* event)
{
	process_event(event);
	return 0;
}

void user_recieve_nl_msg(void)
{
	pthread_t nlrcv;
	int sock_fd;
	struct sockaddr_nl user_sockaddr;
	struct nlmsghdr *nl_msghdr;
	struct msghdr msghdr;

	int result;
	sock_fd = socket(PF_NETLINK, SOCK_RAW, NETLINK_RKCD);

	memset(&user_sockaddr, 0, sizeof(user_sockaddr));
	user_sockaddr.nl_family = AF_NETLINK;
	user_sockaddr.nl_pid = getpid();
	user_sockaddr.nl_groups = NETLINK_RKCD_GROUP;

	result = bind(sock_fd, (struct sockaddr*)&user_sockaddr, sizeof(user_sockaddr));

	int len;
	char buf[8092];
	struct iovec iov = { buf, sizeof(buf) };
	struct sockaddr_nl sa;
	struct nlmsghdr *nh;

	pthread_attr_t attr;
	pthread_attr_init(&attr);
	pthread_attr_setschedpolicy(&attr, SCHED_IDLE);
	pthread_attr_setinheritsched(&attr, PTHREAD_EXPLICIT_SCHED);

	static unsigned long j = 0;

	struct msghdr msg = { &sa, sizeof(sa), &iov, 1, NULL, 0, 0 };
	while (result = recvmsg(sock_fd, &msg, 0)) {
		struct log_entry *data = malloc(sizeof(struct log_entry));
		memcpy(data, NLMSG_DATA(&buf), sizeof(struct log_entry));
		pthread_create(&nlrcv, &attr, __process_event, data);
		j++;
		if (!(j % 100))
			printf("RECV %lu\n", j);
	}

	pthread_attr_destroy(&attr);
	close(sock_fd);
}

int main()
{
	user_recieve_nl_msg();

	return 0;
}
