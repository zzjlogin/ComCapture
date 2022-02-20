#include "DataPackProc.h"

DataPackProc::DataPackProc()
	:m_timeStamp("")
	,m_dataLen(0)
	,m_packageType(0)
{

}

QString DataPackProc::byteToHexString(char *str, int size)
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

void DataPackProc::setDataLen(int len)
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

void DataPackProc::setPointer(const u_char *pkt_data)
{
	mp_pkt_content = pkt_data;
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
		return "ICM";
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
