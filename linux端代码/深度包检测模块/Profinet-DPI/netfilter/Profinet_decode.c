/*
 * Profinet_decode.c
 *
 *  Created on: 2017��5��15��
 *      Author: zwj, dl
 */

#include "Profinet_decode.h"
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


#define Profinet_MIN_LEN_SIZE  36
#define Profinet_MAX_LEN_SIZE  1490
//#define Profinet_PORT 135         

/* Other defines */
#define Profinet_PROTOCOL_ID 0
#define  DEBUG

#define NIPQUAD(addr) \
((unsigned char *)&addr)[0], \
((unsigned char *)&addr)[1], \
((unsigned char *)&addr)[2], \
((unsigned char *)&addr)[3]


struct file *fp;

int fd;




//****************************************************************************
//��������ProfinetLenCheck(__u8 *app_data,__u16 app_len)
//���ܣ�Profinet���ݰ����ȼ��
//������__u8 *app_data,__u16 app_len
//����ֵ��Profinet_LEN_OK Profinet_LEN_FAIL
//���ߣ�yrf
//���ڣ�2017-5-15
//��ע��
//****************************************************************************
static int ProfinetLenCheck(__u8 *app_data,__u16 app_len)
{

	if( app_len>=Profinet_MIN_LEN_SIZE && app_len<=Profinet_MAX_LEN_SIZE)
	{
		return Profinet_DATA_LEN_OK;
	}
	else
	{
		return Profinet_DATA_LEN_FAIL;
	}
}


//****************************************************************************
//��������ProfinetIPCheck(const struct sk_buff *skb)
//���ܣ�Profinet���ݰ��˿ڼ��
//������const struct sk_buff *skb
//����ֵ��Profinet_PORT_OK  Profinet_PORT_FAIL
//���ߣ�yrf
//���ڣ�2017-5-15
//��ע��
//****************************************************************************
static int ProfinetPortCheck(const struct sk_buff *skb,const struct xt_Profinet_mtinfo *info)
{
	__u32 sport,dport;
	//�ж�TCP���ݰ��˿��Ƿ�Ϊ135
	sport = GetSrcPort(skb); 
	dport = GetDstPort(skb);
	//if(htons(dport) != htons(Profinet_PORT))
	if(htons(dport) != htons(info->dst_port) || htons(sport) !=htons(info->src_port))
		return Profinet_PORT_FAIL;
		else
		return Profinet_PORT_OK;
}
//****************************************************************************
//��������ProfinetIPCheck(const struct sk_buff *skb)
//���ܣ�Profinet���ݰ�ԴIP��Ŀ��IP��ַ���
//������const struct sk_buff *skb
//����ֵ��Profinet_IP_OK Profinet_IP_FAIL
//���ߣ�yrf
//���ڣ�2017-5-15
//��ע��
//****************************************************************************
/*
static int ProfinetIPCheck(const struct sk_buff *skb, const struct xt_Profinet_mtinfo *info)
{
    __be32 sip,dip;
	sip = GetSrcIp(skb);
	dip= GetDstIp(skb);

	 printk("Packet for source address: %d.%d.%d.%d\nPacket for destination address: %d.%d.%d.%d\n", NIPQUAD(info->src_IP), NIPQUAD(info->dst_IP));
	if(dip!=info->dst_IP || sip!=info->src_IP)
	{
          return Profinet_IP_FAIL;
	}
	 
	 else 
	 {
		return Profinet_IP_OK;
	 }
	  
}
*/

//****************************************************************************
//��������ProfinetDecode(char *app_data, __u16 app_len, __u8 flags)
//���ܣ�Profinet��Ȱ�����
//������char *app_data, __u16 app_len, __u8 flags
//����ֵ��Profinet_FAIL Profinet_OK
//���ߣ�yrf
//���ڣ�2015-5-15
//��ע��
//****************************************************************************
int ProfinetDecode(char *app_data, __u16 app_len,__u8 flags, const struct xt_Profinet_mtinfo *info, const struct sk_buff *skb)
{

    if (app_len < Profinet_MIN_LEN)
        return Profinet_FAIL;



	if(ProfinetLenCheck(app_data,app_len) != Profinet_DATA_LEN_OK)
	{
		#ifdef DEBUG
			printk("Profinet_DATA_len check FAIL\n");
		#endif

		return Profinet_FAIL;
	}
		#ifdef DEBUG
			printk("Profinet_DATA_len check OK\n");
		#endif

	if(ProfinetPortCheck(skb,info) != Profinet_PORT_OK)
	{
		#ifdef DEBUG
			printk("Profinet_PORT check FAIL\n");
		#endif

		return Profinet_FAIL;
	}
		#ifdef DEBUG
			printk("Profinet_PORT check OK\n");
		#endif

/*	if(ProfinetIPCheck(skb, info) != Profinet_IP_OK)
	{
		#ifdef DEBUG
			printk("Profinet_IP check FAIL\n");
		#endif

		return Profinet_FAIL;
	}
		#ifdef DEBUG
			printk("Profinet_IP check OK\n");
		#endif
*/


    return Profinet_OK;
}
