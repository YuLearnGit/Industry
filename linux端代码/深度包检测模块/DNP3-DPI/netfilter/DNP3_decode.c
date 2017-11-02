/*
 * DNP3_decode.c
 *
 *  Created on: 2017��5��15��
 *      Author: zwj, dl
 */

#include "DNP3_decode.h"
#include "general_api.h"

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/in.h>
#include <linux/fs.h>
#include <asm/uaccess.h>


#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/ipv6.h>
#include <linux/netfilter/x_tables.h>
#include <linux/types.h>
#include <linux/netfilter.h>
#include <linux/version.h>
#include <linux/netfilter_ipv4.h>
#include <linux/moduleparam.h>
#include <linux/netfilter_ipv4/ip_tables.h>
#include <linux/init.h>
#include <linux/inet.h>


#define DNP3_MIN_LEN_SIZE  5
#define DNP3_MAX_LEN_SIZE  255
#define DNP3_PORT 20000            

/* Other defines */
#define DNP3_PROTOCOL_ID 0
#define  DEBUG

#define NIPQUAD(addr) \
((unsigned char *)&addr)[0], \
((unsigned char *)&addr)[1], \
((unsigned char *)&addr)[2], \
((unsigned char *)&addr)[3]


struct file *fp;

int fd;




//****************************************************************************
//��������DNP3LenCheck(__u8 *app_data,__u16 app_len)
//���ܣ�DNP3���ݰ����ȼ��
//������__u8 *app_data,__u16 app_len
//����ֵ��DNP3_LEN_OK DNP3_LEN_FAIL
//���ߣ�yrf
//���ڣ�2017-5-15
//��ע��
//****************************************************************************
static int DNP3LenCheck(__u8 *app_data,__u16 app_len)
{

	if( app_len>=DNP3_MIN_LEN_SIZE && app_len<=DNP3_MAX_LEN_SIZE)
	{
		return DNP3_DATA_LEN_OK;
	}
	else
	{
		return DNP3_DATA_LEN_FAIL;
	}
}


//****************************************************************************
//��������DNP3IPCheck(const struct sk_buff *skb)
//���ܣ�DNP3���ݰ��˿ڼ��
//������const struct sk_buff *skb
//����ֵ��DNP3_PORT_OK  DNP3_PORT_FAIL
//���ߣ�yrf
//���ڣ�2017-5-15
//��ע��
//****************************************************************************
static int DNP3PortCheck(const struct sk_buff *skb)
{
	__u32 sport,dport;
	//�ж�TCP���ݰ��˿��Ƿ�Ϊ20000
	sport = GetSrcPort(skb);
	dport = GetDstPort(skb);
	//if(sport != htons(DNP3_PORT) || dport != htons(DNP3_PORT))
	if(dport != htons(DNP3_PORT))
		return DNP3_PORT_FAIL;
		else
		return DNP3_PORT_OK;
}
//****************************************************************************
//��������DNP3IPCheck(const struct sk_buff *skb)
//���ܣ�DNP3���ݰ�ԴIP��Ŀ��IP��ַ���
//������const struct sk_buff *skb
//����ֵ��DNP3_IP_OK DNP3_IP_FAIL
//���ߣ�yrf
//���ڣ�2017-5-15
//��ע��
//****************************************************************************
/*
static int DNP3IPCheck(const struct sk_buff *skb, const struct xt_DNP3_mtinfo *info)
{
    __be32 sip,dip;
	sip = GetSrcIp(skb);
	dip= GetDstIp(skb);

	 printk("Packet for source address: %d.%d.%d.%d\nPacket for destination address: %d.%d.%d.%d\n", NIPQUAD(info->src_IP), NIPQUAD(info->dst_IP));
	if(dip!=info->dst_IP || sip!=info->src_IP)
	{
          return DNP3_IP_FAIL;
	}
	 
	 else 
	 {
		return DNP3_IP_OK;
	 }
	  
}
*/

//****************************************************************************
//��������DNP3Decode(char *app_data, __u16 app_len, __u8 flags)
//���ܣ�DNP3��Ȱ�����
//������char *app_data, __u16 app_len, __u8 flags
//����ֵ��DNP3_FAIL DNP3_OK
//���ߣ�yrf
//���ڣ�2015-5-15
//��ע��
//****************************************************************************
int DNP3Decode(char *app_data, __u16 app_len, __u8 flags, const struct xt_DNP3_mtinfo *info, const struct sk_buff *skb)
{

    if (app_len < DNP3_MIN_LEN)
        return DNP3_FAIL;



	if(DNP3LenCheck(app_data,app_len) != DNP3_DATA_LEN_OK)
	{
		#ifdef DEBUG
			printk("DNP3_DATA_len check FAIL\n");
		#endif

		return DNP3_FAIL;
	}
		#ifdef DEBUG
			printk("DNP3_DATA_len check OK\n");
		#endif

	if(DNP3PortCheck(skb) != DNP3_PORT_OK)
	{
		#ifdef DEBUG
			printk("DNP3_PORT check FAIL\n");
		#endif

		return DNP3_FAIL;
	}
		#ifdef DEBUG
			printk("DNP3_PORT check OK\n");
		#endif

/*	if(DNP3IPCheck(skb, info) != DNP3_IP_OK)
	{
		#ifdef DEBUG
			printk("DNP3_IP check FAIL\n");
		#endif

		return DNP3_FAIL;
	}
		#ifdef DEBUG
			printk("DNP3_IP check OK\n");
		#endif
*/


    return DNP3_OK;
}
