#pragma once
#include "DataFormat.h"
#include <QString>
#include <QDebug>
#include <QMetaType>
#include <QObject>
#include <WinSock2.h>
//#include <ws2def.h>
//#include <winsock2.h>


class DataPackProc 
{

public:
	DataPackProc();
	~DataPackProc();

private:
	u_int m_dataLen;
	QString m_timeStamp;
	QString m_info;
	int m_packageType;

protected:
	static QString byteToHexString(u_char *str, int size);
public:
	const u_char *mp_pkt_content;
public:
	void setDataLen(u_int len);
	void setTimeStamp(QString time);
	void setInfo(QString infoStr);
	void setPointer(const u_char *pkt_data,int size);
	void setPackType(int type);

	QString getDataLen();
	QString getTimeStamp();
	QString getInfo();
	QString getPackType();

    QString getDstIpAddr();

    QString getSrcIpAddr();

    QString getDstMacAddr();

    QString getSrcMacAddr();

    QString getSrc();

    QString getDst();

    QString getMacType();

    QString getIpVersion();

};

Q_DECLARE_METATYPE(DataPackProc);
