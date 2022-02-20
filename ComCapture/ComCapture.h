#pragma once

#include <QtWidgets/QMainWindow>
#include "ui_ComCapture.h"

#include <QRegularExpression>
#include <QDebug>
#include "pcap.h"
#include "winsock2.h"

#include "DataCaptureThread.h"
#include "DataPackProc.h"
#include "DataFormat.h"

#include <QVector>
#include <QColor>
#include <QTableWidget>

class ComCapture : public QMainWindow
{
    Q_OBJECT

public:
    ComCapture(QWidget *parent = Q_NULLPTR);
	~ComCapture();

public slots:

	void on_action_startAndStop_triggered();

	void on_comboBox_currentIndexChanged(int index);

	void on_dataProc_handle(DataPackProc *data);

    void on_tw_show_cellClicked(int r, int c);

private:
    Ui::ComCaptureClass ui;

	bool isStop=true;

	pcap_if_t *all_device;
	pcap_if_t *device;
	pcap_t *m_ptr;

	char errbuf[PCAP_ERRBUF_SIZE];

	DataCaptureThread *mp_dataCaptueThread;

	QVector<DataPackProc*> m_allData;
	int countNum;

    int numRow;

private:
	int initUi();

	int showNetCard();

	int captureData();

	int startCapture();

	int stopCapture();

};
