// SPDX-License-Identifier: Apache-2.0
/*
 * based on: https://stackoverflow.com/questions/3299386/how-to-use-netlink-socket-to-communicate-with-a-kernel-module
 *
 * A kernel module that uses a netlink socket to receive commands
 * and send responses to a userspace program. See logs with `dmesg`.
 */
#include <linux/module.h> /* Needed by all modules */
#include <linux/kernel.h> /* Needed for KERN_INFO */
#include <net/sock.h>
#include <linux/netlink.h>
#include <linux/skbuff.h>
#include <linux/string.h>

#include "test_kmod.h"

struct sock *nl_sk = NULL;

// report back to userspace
static void send_response(struct nlmsghdr *nlh, char *msg)
{
	int             msg_size = strlen(msg);
	int             pid      = nlh->nlmsg_pid; // pid of sending process
	struct sk_buff *skb_out  = nlmsg_new(msg_size, 0);
	int             res;

	if (!skb_out) {
		printk(KERN_ERR "Failed to allocate new skb\n");
		return;
	}

	nlh = nlmsg_put(skb_out, 0, 0, NLMSG_DONE, msg_size, 0);
	NETLINK_CB(skb_out).dst_group = 0; // not in mcast group
	memcpy(nlmsg_data(nlh), msg, msg_size);

	res = nlmsg_unicast(nl_sk, skb_out, pid);
	if (res)
		printk(KERN_ERR "Error: %d while sending back to user\n", res);
}

// execute a command and report result
static char *execute_cmd(char *cmd)
{
	char *reply = NULL;
	if (strncmp(cmd, CMD_REQUEST_MODULE, strlen(CMD_REQUEST_MODULE)) == 0) {
		int err = request_module("a fake module");
		if (err == -1) {
			printk(KERN_ERR "Request module permission denied: %d\n", err);
			reply = RESPONSE_DENIED;
		} else if (err) {
			printk(KERN_ERR "Request module failed: %d\n", err);
			reply = RESPONSE_ERROR;
		} else {
			reply = RESPONSE_OK;
		}
	} else if (strncmp(cmd, CMD_TEST, strlen(CMD_TEST)) == 0) {
		reply = RESPONSE_OK;
	} else {
		reply = RESPONSE_CMD_UNKNOWN;
	}
	return reply;
}

static void process_msg(struct sk_buff *skb)
{
	struct nlmsghdr *nlh;
	char            *reply;

	printk(KERN_INFO "Entering: %s\n", __FUNCTION__);
	// Get cmd from userspace
	nlh = (struct nlmsghdr *)skb->data;
	printk(KERN_INFO "Netlink received msg payload:%s\n",
	       (char *)nlmsg_data(nlh));

	// Process cmd
	reply = execute_cmd((char *)nlmsg_data(nlh));

	// Respond to userspace
	send_response(nlh, reply);
	printk(KERN_INFO "Exiting: %s\n", __FUNCTION__);
}

static int __init test_kmod_init(void)
{
	printk("Entering: %s\n", __FUNCTION__);
	// run this function when receiving data from netlink socket
	struct netlink_kernel_cfg cfg = {
		.input = process_msg,
	};

	nl_sk = netlink_kernel_create(&init_net, NETLINK_USER, &cfg);
	if (!nl_sk) {
		printk(KERN_ALERT "Error creating socket.\n");
		return -10;
	}

	return 0;
}

static void __exit test_kmod_exit(void)
{
	printk(KERN_INFO "exiting hello module\n");
	netlink_kernel_release(nl_sk);
}

module_init(test_kmod_init);
module_exit(test_kmod_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION(
	"This is a test kernel module that is sent a predefined command from userspace and executes it");
