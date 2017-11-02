/*
 * EtherCAT_decode.c
 *
 *  Created on: 2017��5��15��
 *      Author: zwj, dl
 */

#include "EtherCAT_decode.h"
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


#define EtherCAT_MIN_LEN_SIZE  36
#define EtherCAT_MAX_LEN_SIZE  1490
//#define EtherCAT_PORT 135         

/* Other defines */
#define EtherCAT_PROTOCOL_ID 0
#define  DEBUG

#define NIPQUAD(addr) \
((unsigned char *)&addr)[0], \
((unsigned char *)&addr)[1], \
((unsigned char *)&addr)[2], \
((unsigned char *)&addr)[3]


struct file *fp;

int fd;




//****************************************************************************
//��������EtherCATLenCheck(__u8 *app_data,__u16 app_len)
//���ܣ�EtherCAT���ݰ����ȼ��
//������__u8 *app_data,__u16 app_len
//����ֵ��EtherCAT_LEN_OK EtherCAT_LEN_FAIL
//���ߣ�yrf
//���ڣ�2017-5-15
//��ע��
//****************************************************************************
static int EtherCATLenCheck(__u8 *app_data,__u16 app_len)
{

	if( app_len>=EtherCAT_MIN_LEN_SIZE && app_len<=EtherCAT_MAX_LEN_SIZE)
	{
		return EtherCAT_DATA_LEN_OK;
	}
	else
	{
		return EtherCAT_DATA_LEN_FAIL;
	}
}


//****************************************************************************
//��������EtherCATIPCheck(const struct sk_buff *skb)
//���ܣ�EtherCAT���ݰ��˿ڼ��
//������const struct sk_buff *skb
//����ֵ��EtherCAT_PORT_OK  EtherCAT_PORT_FAIL
//���ߣ�yrf
//���ڣ�2017-5-15
//��ע��
//****************************************************************************
static int EtherCATPortCheck(const struct sk_buff *skb,const struct xt_EtherCAT_mtinfo *info)
{
	__u32 sport,dport;
	//�ж�TCP���ݰ��˿��Ƿ�Ϊ135
	sport = GetSrcPort(skb); 
	dport = GetDstPort(skb);
	//if(htons(dport) != htons(EtherCAT_PORT))
	if(htons(dport) != htons(info->dst_port) || htons(sport) !=htons(info->src_port))
		return EtherCAT_PORT_FAIL;
		else
		return EtherCAT_PORT_OK;
}
//****************************************************************************
//��������EtherCATIPCheck(const struct sk_buff *skb)
//���ܣ�EtherCAT���ݰ�ԴIP��Ŀ��IP��ַ���
//������const struct sk_buff *skb
//����ֵ��EtherCAT_IP_OK EtherCAT_IP_FAIL
//���ߣ�yrf
//���ڣ�2017-5-15
//��ע��
//****************************************************************************
/*
static int EtherCATIPCheck(const struct sk_buff *skb, const struct xt_EtherCAT_mtinfo *info)
{
    __be32 sip,dip;
	sip = GetSrcIp(skb);
	dip= GetDstIp(skb);

	 printk("Packet for source address: %d.%d.%d.%d\nPacket for destination address: %d.%d.%d.%d\n", NIPQUAD(info->src_IP), NIPQUAD(info->dst_IP));
	if(dip!=info->dst_IP || sip!=info->src_IP)
	{
          return EtherCAT_IP_FAIL;
	}
	 
	 else 
	 {
		return EtherCAT_IP_OK;
	 }
	  
}
*/

//****************************************************************************
//��������EtherCATDecode(char *app_data, __u16 app_len, __u8 flags)
//���ܣ�EtherCAT��Ȱ�����
//������char *app_data, __u16 app_len, __u8 flags
//����ֵ��EtherCAT_FAIL EtherCAT_OK
//���ߣ�yrf
//���ڣ�2015-5-15
//��ע��
//****************************************************************************
int EtherCATDecode(char *app_data, __u16 app_len,__u8 flags, const struct xt_EtherCAT_mtinfo *info, const struct sk_buff *skb)
{

    if (app_len < EtherCAT_MIN_LEN)
        return EtherCAT_FAIL;



	if(EtherCATLenCheck(app_data,app_len) != EtherCAT_DATA_LEN_OK)
	{
		#ifdef DEBUG
			printk("EtherCAT_DATA_len check FAIL\n");
		#endif

		return EtherCAT_FAIL;
	}
		#ifdef DEBUG
			printk("EtherCAT_DATA_len check OK\n");
		#endif

	if(EtherCATPortCheck(skb,info) != EtherCAT_PORT_OK)
	{
		#ifdef DEBUG
			printk("EtherCAT_PORT check FAIL\n");
		#endif

		return EtherCAT_FAIL;
	}
		#ifdef DEBUG
			printk("EtherCAT_PORT check OK\n");
		#endif

/*	if(EtherCATIPCheck(skb, info) != EtherCAT_IP_OK)
	{
		#ifdef DEBUG
			printk("EtherCAT_IP check FAIL\n");
		#endif

		return EtherCAT_FAIL;
	}
		#ifdef DEBUG
			printk("EtherCAT_IP check OK\n");
		#endif
*/


    return EtherCAT_OK;
}
