### Sniffer
Implementing a simple sniffer with MFC  

环境:  
 - Windows 10  
 - Npcap SDK 1.01  
 - VS2017  

一直想写一个Windows下抓包的工具，但不会Windows下的开发，查了一些资料，实现Npcap + MFC的Sniffer工具。  

当前功能:  
 - 列取主机中的网卡  
    无线网卡并未列出，原因还未查出  

 - 协议过滤  
    TCP、UDP、ARP、ICMP  

 - 保存Pcap  

 - 读取Pcap  
    修复读取Pcap后，触发`请选择合适网卡`或再次触发`读取`场景时，数据异常访问，导致软件崩溃的问题  

 - 统计数据  
    数据详情设置为只读  

 - HEX显示  
    支持每8个字节数据分隔  

实现截图:  
![Sniffer](https://github.com/Applenice/Sniffer/blob/master/img/Sniffer.png)  

参考litingli写的系列文档实现，就不一一列出:  
1、[一步一步开发sniffer（Winpcap+MFC）（一）工欲善其事，必先配环境——配置winpcap开发环境](https://blog.csdn.net/litingli/article/details/5950962)  
