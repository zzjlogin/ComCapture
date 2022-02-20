#pragma once

#include <QObject>
#include <QThread>
#include <QDebug>
#include <QMetaType>
#include <winsock2.h>

#include "pcap.h"
#include "DataFormat.h"
#include "DataPackProc.h"

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

	int ipPackHandle(const u_char *pkt_content, int &ipPack);

	int tcpPackHandle(const u_char *pkt_content, QString &info, int ipPack);

	int udpPackHandle(const u_char *pkt_content, QString &info);

	QString arpPackHandle(const u_char *pkt_content);

    QString dnsPackHandle(const u_char *pkt_content);

    QString icmpPackHandle(const u_char *pkt_content);

protected:
	void run();

protected:
    static QString byteToHexString(u_char *str, int size);

private:
	bool isStop = true;
	pcap_t *m_ptr;
	struct pcap_pkthdr *header;
	const u_char *pkt_data;
	time_t local_time_sec;
	struct tm local_time;
	char timeString[16];
	
signals:
	void sendDataPackege(DataPackProc *dataPro);


};
