#include "ComCapture.h"
#include <QMetaType>
#include "DataPackProc.h"
ComCapture::ComCapture(QWidget *parent)
    : QMainWindow(parent)
    , mp_dataCaptueThread(new DataCaptureThread)
    , countNum(0)
    , numRow(-1)
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
        if (countNum != 0)
        {
            for (int i = 0; i < m_allData.size(); i++)
            {
                delete m_allData[i];
                m_allData[i] = nullptr;
            }
            m_allData.clear();
            QVector<DataPackProc*>swap(m_allData);
            ui.tw_show->clearContents();
            ui.tw_show->setRowCount(0);
            countNum = 0;
        }

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
        for (device = all_device; i < index - 1; device = device->next, i++);
    }
}


void ComCapture::on_dataProc_handle(DataPackProc *data)
{
    m_allData.push_back(data);
    ui.tw_show->insertRow(countNum);
    QString type = data->getPackType();
    QColor color;
    if (type == "TCP")
    {
        color.setRgb(216, 191, 216);
    }
    else if (type == "UDP")
    {
        color.setRgb(144, 238, 144);
    }
    else if (type == "ARP")
    {
        color.setRgb(238, 238, 0);
    }
    else if (type == "DNS")
    {
        color.setRgb(255, 255, 224);
    }
    else if (type == "ICMP")
    {
        color.setRgb(255, 0, 224);
    }
    else
    {
        color.setRgb(225, 182, 193);
    }

    ui.tw_show->setItem(countNum, 0, new QTableWidgetItem(QString::number(countNum)));
    ui.tw_show->setItem(countNum, 1, new QTableWidgetItem(data->getTimeStamp()));
    ui.tw_show->setItem(countNum, 2, new QTableWidgetItem(data->getSrc()));
    ui.tw_show->setItem(countNum, 3, new QTableWidgetItem(data->getDst()));
    ui.tw_show->setItem(countNum, 4, new QTableWidgetItem(type));
    ui.tw_show->setItem(countNum, 5, new QTableWidgetItem(data->getDataLen()));
    ui.tw_show->setItem(countNum, 6, new QTableWidgetItem(data->getInfo()));

    for (size_t i = 0; i < 7; i++)
    {
        ui.tw_show->item(countNum, i)->setBackgroundColor(color);
    }
    countNum++;
    //自动追踪底部
    //ui.tw_show->scrollToBottom();
    //回到顶端
    //ui.tw_show->scrollToTop();
    /*QString c = data->getDataLen();
    QString t = data->getInfo();
    qDebug() << data->getTimeStamp() <<data->getInfo();*/
}

void ComCapture::on_tw_show_cellClicked(int r, int c)
{
    if (r == numRow || r < 0)
    {
        return;
    }
    else
    {
        ui.treeW_show->clear();
        numRow = r;
        if (numRow < 0 || numRow > countNum)
        {
            return;
        }
        QString dstMac = m_allData[numRow]->getDstMacAddr();
        QString srcMac = m_allData[numRow]->getSrcMacAddr();
        QString type = m_allData[numRow]->getMacType();
        QString tree = "Ethernet Ⅱ,Src:" + srcMac + " Dst:" + dstMac;
        QTreeWidgetItem *item = new QTreeWidgetItem(QStringList() << tree);
        ui.treeW_show->addTopLevelItem(item);
        item->addChild(new QTreeWidgetItem(QStringList() << "Destination:" + dstMac));
        item->addChild(new QTreeWidgetItem(QStringList() << "Source:" + srcMac));
        item->addChild(new QTreeWidgetItem(QStringList() << "Type:" + type));


    }


}

//void ComCapture::on_dataProc_handle(DataPackProc data)
//{
//	ui.tableWidget->insertRow(countNum);
//
//}

int ComCapture::initUi()
{

    ui.action_startAndStop->setIcon(QIcon("images/start.png"));
    showNetCard();
    ui.statusBar->showMessage("welcome use this tool!");
    ui.mainToolBar->addAction(ui.action_startAndStop);

    static bool index = false;
    //qRegisterMetaType< DataPackProc >("DataPackProc");
    connect(mp_dataCaptueThread, &DataCaptureThread::sendDataPackege, this, &ComCapture::on_dataProc_handle);
    ui.mainToolBar->setMovable(false);
    ui.tw_show->setColumnCount(7);
    ui.tw_show->verticalHeader()->setDefaultSectionSize(30);
    QStringList title = { "NO","Time","Src","Dst","Protocal","len","Info" };
    ui.tw_show->setHorizontalHeaderLabels(title);
    ui.tw_show->setColumnWidth(0, 50);
    ui.tw_show->setColumnWidth(1, 80);
    ui.tw_show->setColumnWidth(2, 100);
    ui.tw_show->setColumnWidth(3, 100);
    ui.tw_show->setColumnWidth(4, 100);
    ui.tw_show->setColumnWidth(5, 100);
    ui.tw_show->setColumnWidth(6, 400);

    ui.tw_show->setShowGrid(false);
    ui.tw_show->verticalHeader()->setVisible(false);
    ui.tw_show->setSelectionBehavior(QAbstractItemView::SelectRows);

    ui.treeW_show->resize(500, 20);

    return 0;
}

int ComCapture::showNetCard()
{

    int n = pcap_findalldevs(&all_device, errbuf);
    ui.comboBox->addItem("error: ", errbuf);
    if (n == -1) {
        ui.comboBox->addItem("error: " + QString(errbuf));
    }
    else
    {
        ui.comboBox->clear();
        ui.comboBox->addItem("pls choose card!");
        for (device = all_device; device != nullptr; device = device->next)
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
        ui.treeW_show->clear();
        ui.action_startAndStop->setText("暂停");
        ui.action_startAndStop->setIcon(QIcon("images/stop.png"));
        isStop = !isStop;
        captureData();
        mp_dataCaptueThread->setPointer(m_ptr);
        mp_dataCaptueThread->start();
        ui.comboBox->setDisabled(true);
    }
    return 0;
}

int ComCapture::stopCapture()
{
    ui.action_startAndStop->setText("开始");
    ui.action_startAndStop->setIcon(QIcon("images/start.png"));
    isStop = !isStop;
    mp_dataCaptueThread->stopCapture();
    ui.comboBox->setDisabled(false);
    return 0;
}
