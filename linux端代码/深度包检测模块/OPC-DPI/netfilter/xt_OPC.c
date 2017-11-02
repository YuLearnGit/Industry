/*
 * xt_OPC.c
 *
 *  Created on: 2015��6��15��
 *      Author: zwj, dl
 */

#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/ipv6.h>
#include <linux/netfilter/x_tables.h>
#include <linux/types.h>
#include <linux/netfilter.h>
#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/netfilter_ipv4.h>
#include <linux/moduleparam.h>
#include <linux/netfilter_ipv4/ip_tables.h>
#include <linux/init.h>
#include <linux/inet.h>
#include <linux/in.h>

#include "OPC_decode.h"
#include "general_api.h"

#define  DEBUG

#define REQ_FOR_CONNECTION	1
#define RES_CONNECTION		1
#define ESTABLISHED			1

#define OPC_PORT		135

#define NIPQUAD(addr) \
((unsigned char *)&addr)[0], \
((unsigned char *)&addr)[1], \
((unsigned char *)&addr)[2], \
((unsigned char *)&addr)[3]

static bool OPC_mt4(const struct sk_buff *skb, struct xt_action_param *par)
{

	char *p_data;
	__be32 sip, dip;
	__u32 sport,dport;
	__u8 data_src_flag;
	__u16 app_len = 0;//Ӧ�ò����ݳ���
	char *data_start;//Ӧ�ò�������ʼλ��
	__u16 total_len = 0;

	const struct xt_OPC_mtinfo *info = par->matchinfo;

	if(!skb)
		return false;

	sip = GetSrcIp(skb);
	dip= GetDstIp(skb);
	//�ж����ݰ��Ƿ�ΪTCP���ݰ�
	if( !IsTcpPacket(skb))
		return false;


	sport = GetSrcPort(skb);
	dport = GetDstPort(skb);

	//������Ҫ�޸ģ���Ҫʵ�� �ж�״̬λ�����Ϊ������Լ�Ӧ�����ֱ��ͨ�������Ϊ���ݰ�����Ҫ������Ȱ�����
	//�ж�TCP���ݰ�״̬��
	//���ΪPSH����λ���������Ȱ�����;
	if( !IsTcpFlagPshSet(skb) )
		return true;

	//�ж������ǿͻ������ݻ��Ƿ�����������
	if(sport == htons(OPC_PORT))
		data_src_flag = FROM_CLIENT_FLAG;
	else if(dport == htons(OPC_PORT))
		data_src_flag = FROM_SERVER_FLAG;

	//��֪��Ҫ��Ҫ�ӣ����źø߶ˣ�Ȼ��ͼ�����
	if(skb_is_nonlinear(skb))
	{
		if(skb_linearize(skb) != 0)
	    	printk(KERN_INFO"skb_linearize failed.\n");
	}

	//��ȡӦ�ò����ݳ���
	app_len = GetAppDataLength(skb);

	//��ȡӦ�ò���ʼλ��
	data_start = GetAppData(data_start, skb);

	//��ȡ�����ܳ���
	total_len = (skb->len - skb->data_len);

	#ifdef DEBUG
		printk("\n\n===============start==============\n");


	//��ӡӦ�ò�����
	printk("app_data_len=%d,total_data_len=%d\n",app_len,total_len);
	printk("Packet for source address: %d.%d.%d.%d\nPacket for destination address: %d.%d.%d.%d\n", NIPQUAD(sip), NIPQUAD(dip));
	printk("Packet for source port: %d\nPacket for destination port: %d\n", htons(sport),htons(dport) );
	printk("app_data: ");

	for( p_data = data_start; p_data < (skb->tail);p_data++)
	{
		printk("%02x ", (__u8) *p_data);
	}
    #endif

	#ifdef DEBUG
		printk("\n\n");
		printk("*********OPC dpi********\n");
	#endif

	if ( OPCDecode(data_start, app_len, data_src_flag, info,skb) == OPC_FAIL)
	{
		#ifdef DEBUG
			printk("OPC decode: not OPC proto !!! Failed!!! \n");
			printk("================end==============\n");
		#endif

		return false;
	}
    else
    {
		#ifdef DEBUG
    		printk("OPC decode: OPC proto !!! Success!!! \n");
    	    printk("================end==============\n");
		#endif

    	return true;
    }



}

static struct xt_match OPC_mt_reg __read_mostly = {
		.name      = "OPC",
		.revision  = 1,
		.family    = NFPROTO_IPV4,
		.match     = OPC_mt4,
		.matchsize = sizeof(struct xt_OPC_mtinfo),
		.me        = THIS_MODULE,
};

static int __init OPC_mt_init(void)
{
	#ifdef DEBUG
		printk("register match successed\n");
	#endif
	return xt_register_match(&OPC_mt_reg);
}

static void __exit OPC_mt_exit(void)
{
	#ifdef DEBUG
		printk("unregister match successed\n");
	#endif
	xt_unregister_match(&OPC_mt_reg);
}

module_init(OPC_mt_init);
module_exit(OPC_mt_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("YRF");
MODULE_DESCRIPTION("iptables:OPC detection");
MODULE_ALIAS("ipt_OPC");
MODULE_ALIAS("ip6t_OPC");
