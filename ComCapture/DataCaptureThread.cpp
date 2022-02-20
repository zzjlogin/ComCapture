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
		info = "IP";
		return 1;
		break;
	}
	case 0x0806: {
		info = "Arp";
		return 1;
		break;
	}
	default:
		info = "";
		return 0;
		break;
	}
	return 0;

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
			//int type = etherPackageHandle(pkt_data, info);
			qDebug() << info;
			qDebug() << timeString;
		}

	}
	isStop = !isStop;
}
