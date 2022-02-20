#pragma once

#include <QObject>
#include <QThread>
#include <QDebug>

#include "pcap.h"
#include "DataFormat.h"
#include "DataPackProc.h"
#include <Windows.h>
#include <winsock2.h>
#include <winsock.h>
class DataCaptureThread : public QThread
{
	Q_OBJECT

public:
	DataCaptureThread(QObject *parent=nullptr);

	~DataCaptureThread();

	bool stopCapture();

	bool setPointer(pcap_t * ptr);
	
	bool isStart();


	int etherPackageHandle(const u_char *pkt_content, QString &info);

protected:
	void run();


private:
	bool isStop = true;
	pcap_t *m_ptr;
	struct pcap_pkthdr *header;
	const u_char *pkt_data;
	time_t local_time_sec;
	struct tm local_time;
	char timeString[16];
	


};
