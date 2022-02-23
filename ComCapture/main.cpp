#include "ComCapture.h"
#include <QtWidgets/QApplication>
#include <QFile>

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    ComCapture w;
    w.show();

    //设置qss文件打开路径
    QFile qss("./config/Water.qss");

    //只读，打开qss文件
    qss.open(QFile::ReadOnly);
    if (qss.isOpen())
    {//如果打开成功，设置样式
        w.setStyleSheet(qss.readAll());
        qss.close();//关闭qss文件
    }
    return a.exec();
}
