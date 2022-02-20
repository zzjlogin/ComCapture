# ComCapture

## 环境

- vs:vs2017企业版
- qt：[Qt5.12.12](https://download.qt.io/archive/qt/5.12/5.12.12/qt-opensource-windows-x86-5.12.12.exe)
- wincap：[WinPcap_4_1_3.exe](https://www.winpcap.org/install/bin/WinPcap_4_1_3.exe)
- WpdPack：[WpdPack_4_1_2.zip](https://www.winpcap.org/install/bin/WpdPack_4_1_2.zip)


qt其他版本下载：
    
    - https://download.qt.io/archive/qt/5.12/5.12.12/

## 环境配置

- WpdPack_4_1_2文件解压
- vs2017工程，右键->配置属性->VC++目录(包含目录添加WpdPack\include；库目录添加WpdPack\Lib)
- vs2017工程，右键->配置属性->连接器->输入(附加依赖项：wpcap.lib、Ws2_32.lib)



**注意** ：
    
    - 可以把WpdPack_4_1_2解压的库添加到工程目录，方便更换机器使用。
    - **ntohs** 函数需要添加库：Ws2_32.lib，否则编译报错

##协议

相关协议参考： [相关协议标准](./doc/protocals.md)
