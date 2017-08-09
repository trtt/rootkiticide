#include <linux/list.h>
#include <linux/kthread.h>
#include <linux/netlink.h>
#include <net/sock.h>
#include <net/netlink.h>
#include <net/netns/generic.h>
#include "rootkiticide.h"
#include "ringbuf.h"

#define NETLINK_RKCD 31
#define NETLINK_RKCD_GROUP 1

extern int proc_reader;

static unsigned int rkcd_net_id;
static struct task_struct *nl_task;

struct rkcd_net {
	struct sock *sk;
};

extern struct ringbuf rbuf;

static int rkcd_bind(struct net *net, int group)
{
	proc_reader = current->real_parent->pid;
	return 0;
}

static void rkcd_receive(struct sk_buff *skb)
{
	struct nlmsghdr *nlh;
	int len;
	int err;

	nlh = nlmsg_hdr(skb);
	len = skb->len;

	while (nlmsg_ok(nlh, len)) {
		err = 0;
		if (err || (nlh->nlmsg_flags & NLM_F_ACK))
			netlink_ack(skb, nlh, err);

		nlh = nlmsg_next(nlh, &len);
	}
}

static int nl_thread(void *dummy)
{
	const struct net *net = dummy;
	struct rkcd_net *aunet = net_generic(net, rkcd_net_id);
	struct sock *sk = aunet->sk;
	const struct log_entry *entry;
	struct sk_buff *skb;
	struct nlmsghdr *nlh;
	void *data;
	static ulong j = 0;

	while (1) {
		wait_event_interruptible(rbuf.read_wq,
			(entry = ringbuf_read(&rbuf)) || kthread_should_stop());
		if (kthread_should_stop())
			return 0;
		skb = nlmsg_new(sizeof(struct log_entry), GFP_KERNEL);
		if (!skb)
			return 1;
		nlh = nlmsg_put(skb, 0, 0, NLMSG_DONE, sizeof(struct log_entry),
				0);
		/* NETLINK_CB(skb).pid = 0; */
		/* NETLINK_CB(skb).dst_group = NETLINK_RKCD_GROUP; */
		if (!nlh)
			return 1;
		data = nlmsg_data(nlh);
		memcpy(data, entry, sizeof(struct log_entry));
		int ret = nlmsg_multicast(sk, skb, 0, NETLINK_RKCD_GROUP, GFP_KERNEL);
		/* if (ret < 0) */
		/* 	printk("!!! error %i\n", ret); */
		j++;
		if (!(j % 100))
			printk("SEND %lu\n", j);
	}
	return 0;

}

static int rkcd_net_init(struct net *net)
{
	struct netlink_kernel_cfg cfg = {
		.input	= rkcd_receive,
		.bind	= rkcd_bind,
		.flags	= NL_CFG_F_NONROOT_RECV,
		.groups	= NETLINK_RKCD_GROUP,
	};

	struct rkcd_net *aunet = net_generic(net, rkcd_net_id);

	aunet->sk = netlink_kernel_create(net, NETLINK_RKCD, &cfg);
	if (aunet->sk == NULL) {
		return -ENOMEM;
	}
	/* aunet->sk->sk_sndtimeo = MAX_SCHEDULE_TIMEOUT; */

	nl_task = kthread_run(nl_thread, net, "rkcd_nl_writer");

	return 0;
}

static void rkcd_net_exit(struct net *net)
{
	kthread_stop(nl_task);

	struct rkcd_net *aunet = net_generic(net, rkcd_net_id);

	netlink_kernel_release(aunet->sk);
}

static struct pernet_operations rkcd_net_ops = {
	.init = rkcd_net_init,
	.exit = rkcd_net_exit,
	.id = &rkcd_net_id,
	.size = sizeof(struct rkcd_net),
};

int __must_check nl_init(void)
{
	register_pernet_subsys(&rkcd_net_ops);
	return 0;
}

int __must_check nl_cleanup(void)
{
	unregister_pernet_subsys(&rkcd_net_ops);
	return 0;
}
