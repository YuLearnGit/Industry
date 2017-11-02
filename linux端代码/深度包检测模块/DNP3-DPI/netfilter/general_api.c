/*
 * general_api.c
 *
 *  Created on: 2015��6��15��
 *      Author: zwj
 */

#include "general_api.h"

//****************************************************************************
//��������IsTcpPacket(const struct sk_buff *skb)
//���ܣ��ж��Ƿ�ΪTCP���ݰ�
//������struct sk_buff *skb
//����ֵ��bool
//���ߣ�zwj
//���ڣ�2015-6-5
//��ע��
//****************************************************************************
bool IsTcpPacket(const struct sk_buff *skb)
{
	struct iphdr *iph;
	iph  = ip_hdr(skb);
	if(iph->protocol == IPPROTO_TCP)
		return true;
	else return false;
}

//****************************************************************************
//��������IsUdpPacket(const struct sk_buff *skb)
//���ܣ��ж��Ƿ�ΪUDP���ݰ�
//������struct sk_buff *skb
//����ֵ��bool
//���ߣ�zwj
//���ڣ�2015-6-5
//��ע��
//****************************************************************************
bool IsUdpPacket(const struct sk_buff *skb)
{
	struct iphdr *iph;
	iph  = ip_hdr(skb);
	if(iph->protocol == IPPROTO_UDP)
		return true;
	else return false;
}

//****************************************************************************
//��������IsIcmpPacket(const struct sk_buff *skb)
//���ܣ��ж��Ƿ�ΪICMP���ݰ�
//������struct sk_buff *skb
//����ֵ��bool
//���ߣ�zwj
//���ڣ�2015-6-5
//��ע��
//****************************************************************************
bool IsIcmpPacket(const struct sk_buff *skb)
{
	struct iphdr *iph;
	iph  = ip_hdr(skb);
	if(iph->protocol == IPPROTO_ICMP)
		return true;
	else return false;
}

//****************************************************************************
//��������GetSrcIp(const struct sk_buff *skb)
//���ܣ���ȡԴIP
//������struct sk_buff *skb
//����ֵ��__u32
//���ߣ�zwj
//���ڣ�2015-6-5
//��ע��
//****************************************************************************
__u32 GetSrcIp(const struct sk_buff *skb)
{
	__be32 sip;
	struct iphdr *iph;
	iph  = ip_hdr(skb);
	sip = iph->saddr;
	return sip;
}

//****************************************************************************
//��������GetDstIp(const struct sk_buff *skb)
//���ܣ���ȡĿ��IP
//������struct sk_buff *skb
//����ֵ��__u32
//���ߣ�zwj
//���ڣ�2015-6-5
//��ע��
//****************************************************************************
__u32 GetDstIp(const struct sk_buff *skb)
{
	__be32 dip;
	struct iphdr *iph;
	iph  = ip_hdr(skb);
	dip = iph->daddr;
	return dip;
}

//****************************************************************************
//��������GetSrcPort(const struct sk_buff *skb)
//���ܣ���ȡԴ�˿�
//������struct sk_buff *skb
//����ֵ��__u32
//���ߣ�zwj
//���ڣ�2015-6-5
//��ע��
//****************************************************************************
__u32 GetSrcPort(const struct sk_buff *skb)
{
	__u32 sport;
	struct iphdr *iph;
	struct tcphdr *tcph;
	iph  = ip_hdr(skb);
	if(iph->protocol == IPPROTO_TCP)
	{
		tcph = tcp_hdr(skb);
		sport = tcph->source;
	}
	else sport = 0;

	return sport;
}

//****************************************************************************
//��������GetDstPort(const struct sk_buff *skb)
//���ܣ���ȡĿ�Ķ˿�
//������struct sk_buff *skb
//����ֵ��__u32
//���ߣ�zwj
//���ڣ�2015-6-5
//��ע��
//****************************************************************************
__u32 GetDstPort(const struct sk_buff *skb)
{
	__u32 dport;
	struct iphdr *iph;
	struct tcphdr *tcph;
	iph  = ip_hdr(skb);
	if(iph->protocol == IPPROTO_TCP)
	{
		tcph = tcp_hdr(skb);
		dport = tcph->dest;
	}
	else dport = 0;

	return dport;
}

//****************************************************************************
//��������GetAppData(__u8* app_data, const struct sk_buff *skb)
//���ܣ���ȡĿ�Ķ˿�
//������__u8* app_data, const struct sk_buff *skb
//����ֵ��__u8*
//���ߣ�zwj
//���ڣ�2015-6-5
//��ע��__u8* app_dataӦ�ò�����ָ�룻�˺���ʹ�ã� app_data = GetAppData(app_data, skb)
//****************************************************************************
__u8* GetAppData(__u8* app_data, const struct sk_buff *skb)
{
	struct iphdr *iph;
	struct tcphdr *tcph;
	iph  = ip_hdr(skb);
	if(iph->protocol == IPPROTO_TCP)
	{
		tcph = tcp_hdr(skb);
		app_data = ((char *)tcph) + (tcph->doff << 2);
	}
	else app_data = NULL;

	return app_data;
}

//****************************************************************************
//��������GetAppDataLength(const struct sk_buff *skb)
//���ܣ���ȡӦ�ò����ݳ���
//������struct sk_buff *skb
//����ֵ��__u16
//���ߣ�zwj
//���ڣ�2015-6-5
//��ע��
//****************************************************************************
__u16 GetAppDataLength(const struct sk_buff *skb)
{
	__u16 app_len;
	struct iphdr *iph;
	struct tcphdr *tcph;
	iph = ip_hdr(skb);

	if(iph->protocol == IPPROTO_TCP)
	{
		tcph = tcp_hdr(skb);
		app_len = (skb->len) - (skb->data_len) - ((iph->ihl<<2)+ (tcph->doff << 2));
	}
	else app_len = 0;

	return app_len;

}

//****************************************************************************
//��������GetData_U16(__u8* app_data, __u8 position)
//���ܣ���ȡָ����ʼλ�������ֽڵ�����
//������__u8* app_data, __u8 position
//����ֵ��__u16(�����ֽ���ת�����16λ�޷�����������)
//���ߣ�zwj
//���ڣ�2015-6-5
//��ע��app_dataΪӦ�ò�������ʼ��ַ��positionָ����Ҫ���ݵ�λ�ã�ע����Ҫ�����Ƿ񳬳�Ӧ�ò����ݷ�Χ
//****************************************************************************
__u16 GetData_U16(__u8* app_data, __u8 position)
{
	__u16 data;
	data = (__u16) (*(app_data + position));
	data = ntohs(data);

	return data;
}

//****************************************************************************
//��������GetData_U32(__u8* app_data, __u8 position)
//���ܣ���ȡָ����ʼλ���ĸ��ֽڵ�����
//������__u8* app_data, __u8 position
//����ֵ��__u32(�����ֽ���ת�����32λ�޷�����������)
//���ߣ�zwj
//���ڣ�2015-6-5
//��ע��app_dataΪӦ�ò�������ʼ��ַ��positionָ����Ҫ���ݵ�λ�ã�ע����Ҫ�����Ƿ񳬳�Ӧ�ò����ݷ�Χ
//****************************************************************************
__u32 GetData_U32(__u8* app_data, __u8 position)
{
	__u32 data;
	data = (__u32) (*(app_data + position));
	data = ntohs(data);

	return data;
}

//****************************************************************************
//��������IsTcpFlagFinSet(const struct sk_buff *skb)
//���ܣ���ȡTCP���ݰ�Fin״̬
//������struct sk_buff *skb
//����ֵ��bool
//���ߣ�zwj
//���ڣ�2015-6-5
//��ע��
//****************************************************************************
bool IsTcpFlagFinSet(const struct sk_buff *skb)
{
	struct iphdr *iph;
	struct tcphdr *tcph;
	iph = ip_hdr(skb);

	if(iph->protocol == IPPROTO_TCP)
	{
		tcph = tcp_hdr(skb);
		if(tcph->fin == FLAG_SET)
				return true;
		else
			return false;
	}
	else
		return false;
}

//****************************************************************************
//��������IsTcpFlagSynSet(const struct sk_buff *skb)
//���ܣ���ȡTCP���ݰ�Syn״̬
//������struct sk_buff *skb
//����ֵ��bool
//���ߣ�zwj
//���ڣ�2015-6-5
//��ע��
//****************************************************************************
bool IsTcpFlagSynSet(const struct sk_buff *skb)
{
	struct iphdr *iph;
	struct tcphdr *tcph;
	iph = ip_hdr(skb);

	if(iph->protocol == IPPROTO_TCP)
	{
		tcph = tcp_hdr(skb);
		if(tcph->syn == FLAG_SET)
				return true;
		else
			return false;
	}
	else
		return false;
}

//****************************************************************************
//��������IsTcpFlagRstSet(const struct sk_buff *skb)
//���ܣ���ȡTCP���ݰ�Rst״̬
//������struct sk_buff *skb
//����ֵ��bool
//���ߣ�zwj
//���ڣ�2015-6-5
//��ע��
//****************************************************************************
bool IsTcpFlagRstSet(const struct sk_buff *skb)
{
	struct iphdr *iph;
	struct tcphdr *tcph;
	iph = ip_hdr(skb);

	if(iph->protocol == IPPROTO_TCP)
	{
		tcph = tcp_hdr(skb);
		if(tcph->rst == FLAG_SET)
				return true;
		else
			return false;
	}
	else
		return false;
}

//****************************************************************************
//��������IsTcpFlagPshSet(const struct sk_buff *skb)
//���ܣ���ȡTCP���ݰ�Psh״̬
//������struct sk_buff *skb
//����ֵ��bool
//���ߣ�zwj
//���ڣ�2015-6-5
//��ע��
//****************************************************************************
bool IsTcpFlagPshSet(const struct sk_buff *skb)
{
	struct iphdr *iph;
	struct tcphdr *tcph;
	iph = ip_hdr(skb);

	if(iph->protocol == IPPROTO_TCP)
	{
		tcph = tcp_hdr(skb);
		if(tcph->psh == FLAG_SET)
				return true;
		else
			return false;
	}
	else
		return false;
}

//****************************************************************************
//��������IsTcpFlagAckSet(const struct sk_buff *skb)
//���ܣ���ȡTCP���ݰ�Ack״̬
//������struct sk_buff *skb
//����ֵ��bool
//���ߣ�zwj
//���ڣ�2015-6-5
//��ע��
//****************************************************************************
bool IsTcpFlagAckSet(const struct sk_buff *skb)
{
	struct iphdr *iph;
	struct tcphdr *tcph;
	iph = ip_hdr(skb);

	if(iph->protocol == IPPROTO_TCP)
	{
		tcph = tcp_hdr(skb);
		if(tcph->ack == FLAG_SET)
				return true;
		else
			return false;
	}
	else
		return false;
}
