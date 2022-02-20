#include "DataCaptureThread.h"

DataCaptureThread::DataCaptureThread(QObject *parent)
	: QThread(parent)
	,isStop(true)
{

	

}

DataCaptureThread::~DataCaptureThread()
{
	if (this->isStart())
	{
		this->stopCapture();
		this->wait();
	}
}

bool DataCaptureThread::stopCapture()
{
	isStop = !isStop;
	return isStop;
}

bool DataCaptureThread::setPointer(pcap_t * ptr)
{
	if (ptr)
	{
		m_ptr = ptr;

		return true;
	} 
	else
	{
		return false;
	}
}

bool DataCaptureThread::isStart()
{
	return !isStop;
}

int DataCaptureThread::etherPackageHandle(const u_char *pkt_content, QString &info)
{
	Ethernet_Header *ethernet;
	u_short content_type;
	ethernet = (Ethernet_Header*)pkt_content;
	content_type = ntohs(ethernet->type);
	switch (content_type)
	{
	case 0x0800: {
        int ipPackage = 0;
        int res = ipPackHandle(pkt_content, ipPackage);
        switch (res)
        {
        case 1: {//icmp
            info = icmpPackHandle(pkt_content);
            return 2;
        }
        case 6: {//tcp
            return tcpPackHandle(pkt_content, info, ipPackage);
        }
        case 17: {//udp
            return udpPackHandle(pkt_content, info);
        }
        default:
            break;
        }
		break;
	}
	case 0x0806: {
		info = arpPackHandle(pkt_content);
		return 1;
	}
	default:
		info = "";
		return 0;
		break;
	}
	return 0;

}

int DataCaptureThread::ipPackHandle(const u_char *pkt_content, int &ipPack)
{
	IPV4_HEADER *ip;
	ip = (IPV4_HEADER*)(pkt_content + 14);
	int protocal = ip->protocol;
	ipPack = (ntohs(ip->total_length - ((ip->version_IHL)) &0x0F) * 4);
	return protocal;
}

int DataCaptureThread::tcpPackHandle(const u_char *pkt_content, QString &info, int ipPack)
{
	TCP_Header *tcp;
	tcp = (TCP_Header *)(pkt_content + 14 + 20);
	u_short src = ntohs(tcp->src_port);
	u_short dst = ntohs(tcp->dst_port);
	QString portSend("");
	QString portRecv("");

	int type = 3;
	int delta = (tcp->header_length) * 4;
	int tcpLoader = ipPack - delta;

	if (src == 443 || dst == 443)
	{
		if (src == 443)
		{
			portSend = "(https)";
		}
		else
		{
			portRecv = "(https)";
		}
	}
	else
	{
		info += QString::number(src) + portSend + "->" + QString::number(dst) + portRecv;
	}
	QString flag("");
	if (tcp->flags & 0x08)
	{
		flag += "PSH,";
	}
	if (tcp->flags & 0x10)
	{
		flag += "ACK,";
	}
	if (tcp->flags & 0x02)
	{
		flag += "SYN,";
	}
	if (tcp->flags & 0x20)
	{
		flag += "URG,";
	}
	if (tcp->flags & 0x01)
	{
		flag += "FIN,";
	}
	if (tcp->flags & 0x04)
	{
		flag += "RST,";
	}
	if (flag != "")
	{
		flag = flag.left(flag.length() - 1);
		info += "[" + flag + "]";
	}

	u_int sequence = ntohl(tcp->sequence);
	u_int ack = ntohl(tcp->ack);
	u_short window = ntohs(tcp->window_size);

	info += " Seq=" + QString::number(sequence) + " ACK=" + QString::number(ack) + " win=" + QString::number(window) + " len=" + QString::number(tcpLoader);
	return type;
}

int DataCaptureThread::udpPackHandle(const u_char *pkt_content, QString &info)
{
	UDP_HEADER *udp;
	udp = (UDP_HEADER *)(pkt_content + 14 + 20);
	u_short dst = ntohs(udp->dst_port);
	u_short src = ntohs(udp->src_port);
	if (dst ==53|| src == 53)
	{
        info = dnsPackHandle(pkt_content);
		return 5;
	} 
	else
	{
		QString res = QString::number(src) + "->" + QString::number(dst);
		u_short data_len = ntohs(udp->data_length);
		res += " len=" + QString::number(data_len);
		info = res;
		return 4;
	}


}

QString DataCaptureThread::arpPackHandle(const u_char *pkt_content)
{
	ARP_HEADER *arp;
	arp = (ARP_HEADER*)(pkt_content + 14);

	u_short op = ntohs(arp->op_code);
	QString res("");
    u_char *dst_addr = arp->des_ip_addr;
    QString dstIp = QString::number(*dst_addr) + "."
        + QString::number(*(dst_addr + 1)) + "."
        + QString::number(*(dst_addr + 2)) + "."
        + QString::number(*(dst_addr + 3)) + ".";
    u_char *src_addr = arp->src_ip_addr;
    QString srcIp = QString::number(*src_addr) + "."
        + QString::number(*(src_addr + 1)) + "."
        + QString::number(*(src_addr + 2)) + "."
        + QString::number(*(src_addr + 3)) + ".";
    u_char *src_eth = arp->src_eth_addr;
    QString srcEth = byteToHexString(src_eth, 1) + ":"
        + byteToHexString((src_eth + 1), 1) + ":"
        + byteToHexString((src_eth + 2), 1) + ":"
        + byteToHexString((src_eth + 3), 1) + ":"
        + byteToHexString((src_eth + 4), 1) + ":"
        + byteToHexString((src_eth + 5), 1);
    if (op == 1)
    {
        res = "who has " + dstIp + "? Tell" + srcIp;
    }
    else if (op == 2)
    {
        res = srcIp + " is at " + srcIp;
    }
    return res;
}

QString DataCaptureThread::dnsPackHandle(const u_char *pkt_content)
{
    DNS_HEADER *dns;
    dns = (DNS_HEADER *)(pkt_content + 14 + 20 + 8);
    u_short identification = ntohs(dns->identification);
    u_short type = dns->flags;
    QString info("");
    if ((type & 0xF800) == 0x8000)
    {
        info = "Standard query response";
    }
    QString name = "";
    char * domain = (char *)(pkt_content + 14 + 20 + 8 + 12);
    while (*domain != 0x00) {
        if (domain && (*domain) <= 64)
        {
            int length = *domain;
            domain++;
            for (int k = 0; k < length; k++)
            {
                name += (*domain);
            }
            name += ".";
        }
        else
        {
            break;
        }
    }
    if (name != "")
    {
        name = name.left(name.size() - 1);
    }
    return info + QString::number(identification, 16) + " " + name;
}

QString DataCaptureThread::icmpPackHandle(const u_char *pkt_content)
{
    ICMP_HEADER *icmp;
    icmp = (ICMP_HEADER*)(pkt_content + 14 + 20);
    u_char type = icmp->type;
    u_char code = icmp->code;
    QString res("");
    switch (type)
    {
    case 0: {
        if (!code)
        {
            res = "Echo response(ping)";
        }
        break;
    }
    case 8: {
        if (!code)
        {
            res = "Echo request(ping)";
        }
        break;
    }
    default:
        break;
    }
    return res;
}

void DataCaptureThread::run()
{
	isStop = false;
	while (!isStop)
	{
		int res = pcap_next_ex(m_ptr, &header, &pkt_data);
		if (res)
		{
			
			local_time_sec = header->ts.tv_sec;
			localtime_s(&local_time, &local_time_sec);
			strftime(timeString, sizeof timeString, "%H:%M:%S", &local_time);
			QString info;
			int type = etherPackageHandle(pkt_data, info);
			if (type)
			{
				//qDebug() << type;
				DataPackProc *data = new DataPackProc;
				data->setInfo(info);
				data->setDataLen(header->len);
				data->setTimeStamp(timeString);
                data->setPackType(type);
                data->setPointer(pkt_data, header->len);
               // data->setPointer(pkt_data);
				emit sendDataPackege(data);
			}
		
		}

	}
	isStop = !isStop;
}

QString DataCaptureThread::byteToHexString(u_char *str, int size)
{
    QString res("");
    for (int i = 0; i < size; i++)
    {
        char high4 = str[i] >> 4;
        if (high4 >= 0x0A)
        {
            high4 += 0x41 - 0x0A;
        }
        else {
            high4 += 0x30;
        }
        char low4 = str[i] >> 4;
        if (low4 >= 0x0A)
        {
            low4 += 0x41 - 0x0A;
        }
        else {
            low4 += 0x30;
        }
        res.append(high4).append(low4);
    }
    return res;
}
