#include "DataPackProc.h"

DataPackProc::DataPackProc()
	:m_timeStamp("")
	,m_dataLen(0)
	,m_packageType(0)
    ,mp_pkt_content(nullptr)
{
	
	
}

DataPackProc::~DataPackProc()
{
    if (mp_pkt_content)
    {
        delete mp_pkt_content;
        mp_pkt_content = nullptr;
    }
}

QString DataPackProc::byteToHexString(u_char *str, int size)
{
	QString res("");
	for (int i=0;i<size;i++)
	{
		char high4 = str[i] >> 4;
		if (high4>=0x0A)
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

void DataPackProc::setDataLen(u_int len)
{
	m_dataLen = len;
}

void DataPackProc::setTimeStamp(QString time)
{
	m_timeStamp = time;
}

void DataPackProc::setInfo(QString infoStr)
{
	m_info = infoStr;
}

void DataPackProc::setPointer(const u_char *pkt_data, int size)
{
	mp_pkt_content = pkt_data;
    mp_pkt_content = new u_char[size];
    memcpy((char*)mp_pkt_content, pkt_data, size);
}

void DataPackProc::setPackType(int type)
{
	m_packageType = type;
}

QString DataPackProc::getDataLen()
{
	return QString::number(m_dataLen);
}

QString DataPackProc::getTimeStamp()
{
	return m_timeStamp;
}

QString DataPackProc::getInfo()
{
	return m_info;
}

QString DataPackProc::getPackType()
{
	switch (m_packageType)
	{
	case 1:
		return "ARP";
	case 2:
		return "ICMP";
	case 3:
		return "TCP";
	case 4:
		return "UDP";
	case 5:
		return "DNS";
	case 6:
		return "TLS";
	default:
		return "";
		break;
	}

}

QString DataPackProc::getDstIpAddr()
{
    IPV4_HEADER *ip;
    ip = (IPV4_HEADER*)(mp_pkt_content+ 14);
    sockaddr_in addr;
    addr.sin_addr.s_addr = ip->des_addr;
   
    return QString(inet_ntoa(addr.sin_addr));
}

QString DataPackProc::getSrcIpAddr()
{
    IPV4_HEADER *ip;
    ip = (IPV4_HEADER*)(mp_pkt_content + 14);
    sockaddr_in addr;
    addr.sin_addr.s_addr = ip->src_addr;

    return QString(inet_ntoa(addr.sin_addr));
}

QString DataPackProc::getDstMacAddr()
{
    Ethernet_Header *eth;
    eth = (Ethernet_Header*)(mp_pkt_content);
    u_char *addr = eth->ether_dst_host;
    if (addr) {
        QString res = byteToHexString(addr, 1) + ":"
            + byteToHexString((addr + 1), 1) + ":"
            + byteToHexString((addr + 2), 1) + ":"
            + byteToHexString((addr + 3), 1) + ":"
            + byteToHexString((addr + 4), 1) + ":"
            + byteToHexString((addr + 5), 1);
        if (res == "FF:FF:FF:FF:FF:FF")
        {
            return "FF:FF:FF:FF:FF:FF(Broadcast)";
        }
        else
        {
            return res;
        }
    }
    return "";
}

QString DataPackProc::getSrcMacAddr()
{
    Ethernet_Header *eth;
    eth = (Ethernet_Header*)(mp_pkt_content);
    u_char *addr = eth->ether_src_host;
    if (addr) {
        QString res = byteToHexString(addr, 1) + ":"
            + byteToHexString((addr + 1), 1) + ":"
            + byteToHexString((addr + 2), 1) + ":"
            + byteToHexString((addr + 3), 1) + ":"
            + byteToHexString((addr + 4), 1) + ":"
            + byteToHexString((addr + 5), 1);
        if (res == "FF:FF:FF:FF:FF:FF")
        {
            return "FF:FF:FF:FF:FF:FF(Broadcast)";
        }
        else
        {
            return res;
        }
    }
    return "";
}

QString DataPackProc::getSrc()
{
    if (m_packageType == 1)
    {
        return getSrcMacAddr();
    }
    else
    {
        return getSrcIpAddr();
    }
}

QString DataPackProc::getDst()
{
    if (m_packageType == 1)
    {
        return getDstMacAddr();
    }
    else
    {
        return getDstIpAddr();
    }
}

QString DataPackProc::getMacType()
{
    Ethernet_Header * eth;
    eth = (Ethernet_Header*)(mp_pkt_content);
    u_short type = ntohs(eth->type);
    if (type == 0x0800)
    {
        return "IPv4(0x0800)";
    }
    else if (type == 0x0806)
    {
        return "ARP(0x0806)";
    }
    return "";
}

QString DataPackProc::getIpVersion()
{
    Ethernet_Header * eth;
    eth = (Ethernet_Header*)(mp_pkt_content);
    u_short type = ntohs(eth->type);
    if (type == 0x0800)
    {
        IPV4_HEADER * ip;
        ip = (IPV4_HEADER*)(mp_pkt_content + 14);

        return QString::number(ip->version_IHL >> 4);
    }
    return "Not IP Frame";
}

