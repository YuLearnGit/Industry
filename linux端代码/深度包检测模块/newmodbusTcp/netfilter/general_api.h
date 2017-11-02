/*
 * general_api.h
 *
 *  Created on: 2015��6��15��
 *      Author: zwj
 */

#ifndef GENERAL_API_H_
#define GENERAL_API_H_

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

#define FLAG_SET	1
#define FLAG_UNSET	0

//�ж��Ƿ�ΪTCP���ݰ�
bool IsTcpPacket(const struct sk_buff *);

//�ж��Ƿ�ΪUDP���ݰ�
bool IsUdpPackst(const struct sk_buff *);

//�ж��Ƿ�ΪICMP���ݰ�
bool IsIcmpPacket(const struct sk_buff *);

//��ȡԴIP
__u32 GetSrcIp(const struct sk_buff *);

//��ȡĿ��IP
__u32 GetDstIp(const struct sk_buff *);

//��ȡԴ�˿�
__u32 GetSrcPort(const struct sk_buff *);

//��ȡĿ�Ķ˿�
__u32 GetDstPort(const struct sk_buff *);

//��ȡӦ�ò�����
__u8* GetAppData(__u8* , const struct sk_buff *);

//��ȡӦ�ò����ݳ���
__u16 GetAppDataLength(const struct sk_buff *);

//��ȡָ��λ�������ֽڵ�����
__u16 GetData_U16(__u8*, __u8);

//��ȡָ��λ���ĸ��ֽڵ�����
__u32 GetData_U32(__u8*, __u8);

//��ȡTCP���ݰ�Fin״̬
bool IsTcpFlagFinSet(const struct sk_buff *);

//���ܣ���ȡTCP���ݰ�Syn״̬
bool IsTcpFlagSynSet(const struct sk_buff *);

//���ܣ���ȡTCP���ݰ�Rst״̬
bool IsTcpFlagRstSet(const struct sk_buff *);

//���ܣ���ȡTCP���ݰ�Psh״̬
bool IsTcpFlagPshSet(const struct sk_buff *);

//���ܣ���ȡTCP���ݰ�Ack״̬
bool IsTcpFlagAckSet(const struct sk_buff *);



#endif /* GENERAL_API_H_ */
