#pragma once
#include "DataFormat.h"
#include <QString>

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
	static QString byteToHexString(char *str, int size);
public:
	const u_char *mp_pkt_content;
public:
	void setDataLen(int len);
	void setTimeStamp(QString time);
	void setInfo(QString infoStr);
	void setPointer(const u_char *pkt_data);
	void setPackType(int type);

	QString getDataLen();
	QString getTimeStamp();
	QString getInfo();
	QString getPackType();
};

