#include "ComCapture.h"
#include <QtWidgets/QApplication>

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    ComCapture w;
    w.show();
    return a.exec();
}
