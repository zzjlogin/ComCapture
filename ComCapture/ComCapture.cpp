#include "ComCapture.h"

ComCapture::ComCapture(QWidget *parent)
    : QMainWindow(parent)
	,mp_dataCaptueThread(new DataCaptureThread)
{
    ui.setupUi(this);
	initUi();
	this->setWindowTitle("抓包工具");
}

ComCapture::~ComCapture()
{
	delete mp_dataCaptueThread;
	mp_dataCaptueThread = nullptr;
}

void ComCapture::on_action_startAndStop_triggered()
{
	if (isStop)
	{
		startCapture();
	}
	else
	{
		stopCapture();
	}
	
}

void ComCapture::on_comboBox_currentIndexChanged(int index)
{
	int i = 0;
	if (index)
	{
		for (device = all_device; i < index - 1; device = device->next,i++);
		
	}
}

int ComCapture::initUi()
{

	ui.action_startAndStop->setIcon(QIcon("images/start.png"));
	showNetCard();
	
	return 0;
}

int ComCapture::showNetCard()
{

	int n = pcap_findalldevs(&all_device, errbuf);
	ui.comboBox->addItem("error: " ,errbuf);
	if (n == -1) {
		ui.comboBox->addItem("error: " + QString(errbuf));
	}
	else
	{
		ui.comboBox->clear();
		ui.comboBox->addItem("pls choose card!");
		for (device = all_device;device != nullptr;device = device->next)
		{
			QString device_name = device->name;
			device_name = device_name.remove(QRegExp("\\\\Device.*\\}"));
			QString des = device->description;
			QString item = device_name + des;
			ui.comboBox->addItem(item);
		}
	}

	return n;
}

int ComCapture::captureData()
{
	if (device)
	{
		m_ptr = pcap_open_live(device->name, 65535, 1, 1000, errbuf);
	}
	else
	{
		return -1;
	}
	if (!m_ptr)
	{
		pcap_freealldevs(all_device);
		device = nullptr;
		return -1;
	}
	else
	{
		if (pcap_datalink(m_ptr) != DLT_EN10MB)
		{
			pcap_close(m_ptr);
			pcap_freealldevs(all_device);
			device = nullptr;
			m_ptr = nullptr;
			return -1;

		}
	}
	return 0;
}

int ComCapture::startCapture()
{
	if (ui.comboBox->currentIndex() == 0)
	{
		return -1;
	}
	if (isStop)
	{
		ui.action_startAndStop->setText("暂停");
		ui.action_startAndStop->setIcon(QIcon("images/stop.png"));
		isStop = !isStop;


		captureData();

		mp_dataCaptueThread->setPointer(m_ptr);
		mp_dataCaptueThread->start();

	}
	return 0;
}

int ComCapture::stopCapture()
{
	ui.action_startAndStop->setText("开始");
	ui.action_startAndStop->setIcon(QIcon("images/start.png"));
	isStop = !isStop;
	mp_dataCaptueThread->stopCapture();
	return 0;
}
