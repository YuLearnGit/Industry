/*
 * OPC_decode.c
 *
 *  Created on: 2017��5��15��
 *      Author: zwj, dl
 */

#include "OPC_decode.h"
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


#define OPC_MIN_LEN_SIZE  5
#define OPC_MAX_LEN_SIZE  255
#define OPC_PORT 135         

/* Other defines */
#define OPC_PROTOCOL_ID 0
#define  DEBUG

#define NIPQUAD(addr) \
((unsigned char *)&addr)[0], \
((unsigned char *)&addr)[1], \
((unsigned char *)&addr)[2], \
((unsigned char *)&addr)[3]


struct file *fp;

int fd;




//****************************************************************************
//��������OPCLenCheck(__u8 *app_data,__u16 app_len)
//���ܣ�OPC���ݰ����ȼ��
//������__u8 *app_data,__u16 app_len
//����ֵ��OPC_LEN_OK OPC_LEN_FAIL
//���ߣ�yrf
//���ڣ�2017-5-15
//��ע��
//****************************************************************************
static int OPCLenCheck(__u8 *app_data,__u16 app_len)
{

	if( app_len>=OPC_MIN_LEN_SIZE && app_len<=OPC_MAX_LEN_SIZE)
	{
		return OPC_DATA_LEN_OK;
	}
	else
	{
		return OPC_DATA_LEN_FAIL;
	}
}


//****************************************************************************
//��������OPCIPCheck(const struct sk_buff *skb)
//���ܣ�OPC���ݰ��˿ڼ��
//������const struct sk_buff *skb
//����ֵ��OPC_PORT_OK  OPC_PORT_FAIL
//���ߣ�yrf
//���ڣ�2017-5-15
//��ע��
//****************************************************************************
static int OPCPortCheck(const struct sk_buff *skb,const struct xt_OPC_mtinfo *info)
{
	__u32 sport,dport;
	//�ж�TCP���ݰ��˿��Ƿ�Ϊ135
	sport = GetSrcPort(skb); 
	dport = GetDstPort(skb);
	if(htons(dport) != htons(OPC_PORT))
	//if(htons(dport) != htons(info->dst_port) || htons(sport) !=htons(info->src_port))
		return OPC_PORT_FAIL;
		else
		return OPC_PORT_OK;
}
//****************************************************************************
//��������OPCIPCheck(const struct sk_buff *skb)
//���ܣ�OPC���ݰ�ԴIP��Ŀ��IP��ַ���
//������const struct sk_buff *skb
//����ֵ��OPC_IP_OK OPC_IP_FAIL
//���ߣ�yrf
//���ڣ�2017-5-15
//��ע��
//****************************************************************************
/*
static int OPCIPCheck(const struct sk_buff *skb, const struct xt_OPC_mtinfo *info)
{
    __be32 sip,dip;
	sip = GetSrcIp(skb);
	dip= GetDstIp(skb);

	 printk("Packet for source address: %d.%d.%d.%d\nPacket for destination address: %d.%d.%d.%d\n", NIPQUAD(info->src_IP), NIPQUAD(info->dst_IP));
	if(dip!=info->dst_IP || sip!=info->src_IP)
	{
          return OPC_IP_FAIL;
	}
	 
	 else 
	 {
		return OPC_IP_OK;
	 }
	  
}
*/

//****************************************************************************
//��������OPCDecode(char *app_data, __u16 app_len, __u8 flags)
//���ܣ�OPC��Ȱ�����
//������char *app_data, __u16 app_len, __u8 flags
//����ֵ��OPC_FAIL OPC_OK
//���ߣ�yrf
//���ڣ�2015-5-15
//��ע��
//****************************************************************************
int OPCDecode(char *app_data, __u16 app_len, __u8 flags, const struct xt_OPC_mtinfo *info, const struct sk_buff *skb)
{

    if (app_len < OPC_MIN_LEN)
        return OPC_FAIL;



	if(OPCLenCheck(app_data,app_len) != OPC_DATA_LEN_OK)
	{
		#ifdef DEBUG
			printk("OPC_DATA_len check FAIL\n");
		#endif

		return OPC_FAIL;
	}
		#ifdef DEBUG
			printk("OPC_DATA_len check OK\n");
		#endif

	if(OPCPortCheck(skb,info) != OPC_PORT_OK)
	{
		#ifdef DEBUG
			printk("OPC_PORT check FAIL\n");
		#endif

		return OPC_FAIL;
	}
		#ifdef DEBUG
			printk("OPC_PORT check OK\n");
		#endif

/*	if(OPCIPCheck(skb, info) != OPC_IP_OK)
	{
		#ifdef DEBUG
			printk("OPC_IP check FAIL\n");
		#endif

		return OPC_FAIL;
	}
		#ifdef DEBUG
			printk("OPC_IP check OK\n");
		#endif
*/


    return OPC_OK;
}
