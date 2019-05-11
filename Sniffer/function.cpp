#include "stdafx.h"
#include "Sniffer.h"
#include "SnifferDlg.h"
#include "afxdialogex.h"
#include "resource.h"
#include "pcap.h"

DWORD WINAPI CapThread(LPVOID lpParameter);

int CSnifferDlg::InitCap()
{
    devCount = 0;
    if (pcap_findalldevs(&alldev, errbuf) == -1)
        return -1;
    for (dev = alldev; dev; dev = dev->next)
        devCount++;
    return 0;
}

//开始捕获
int CSnifferDlg::StartCap()
{
    int if_index, filter_index, count;
    u_int netmask;
    struct bpf_program fcode;

    InitCap();

    //获得接口和过滤器索引
    if_index = this->m_comboBox.GetCurSel();
    filter_index = this->m_comboBoxRule.GetCurSel();

    if (if_index == 0 || if_index == CB_ERR)
    {
        MessageBox(_T("请选择一个合适的网卡接口"));

        /*处理读包后网卡选择异常的情况，清空读包得到的数据*/
        this->npkt = 1;
        this->m_localDataList.RemoveAll();
        this->m_netDataList.RemoveAll();
        memset(&(this->npacket), 0, sizeof(struct pktcount));
        this->UpdateNPacket();
        this->m_listCtrl.DeleteAllItems();
        this->m_treeCtrl.DeleteAllItems();
        this->m_edit.SetWindowTextW(_T(""));
        this->m_buttonStart.EnableWindow(TRUE);
        this->m_buttonStop.EnableWindow(FALSE);
        this->m_buttonSave.EnableWindow(FALSE);

        return -1;
    }
    if (filter_index == CB_ERR)
    {
        MessageBox(_T("过滤器选择错误"));
        return -1;
    }

    /*获得选中的网卡接口*/
    dev = alldev;
    for (count = 0; count < if_index - 1; count++)
    {
        dev = dev->next;
    }

    /*args: 设备名、捕获数据包长度、混杂模式、读超时设置、错误信息*/
    if ((adhandle = pcap_open_live(dev->name, 65536, 1, 1000, errbuf)) == NULL)
    {
        MessageBox(_T("无法打开接口：" + CString(dev->description)));
        pcap_freealldevs(alldev);
        return -1;
    }

    /*检查是否为以太网*/
    if (pcap_datalink(adhandle) != DLT_EN10MB)
    {
        MessageBox(_T("这不适合于非以太网的网络!"));
        pcap_freealldevs(alldev);
        return -1;
    }

    if (dev->addresses != NULL)
    {
        netmask = ((struct sockaddr_in *)(dev->addresses->netmask))->sin_addr.S_un.S_addr;
    }
    else {
        netmask = 0xffffff;
    }

    //编译过滤器
    if (filter_index == 0)
    {
        char filter[] = "";
        if (pcap_compile(adhandle, &fcode, filter, 1, netmask) < 0)
        {
            MessageBox(_T("语法错误，无法编译过滤器"));
            pcap_freealldevs(alldev);
            return -1;
        }
    }
    else {
        CString str;
        char *filter;
        int len, x;
        this->m_comboBoxRule.GetLBText(filter_index, str);
        len = str.GetLength() + 1;
        filter = (char*)malloc(len);
        for (x = 0; x < len; x++)
        {
            filter[x] = str.GetAt(x);
        }
        if (pcap_compile(adhandle, &fcode, filter, 1, netmask) < 0)
        {
            MessageBox(_T("语法错误，无法编译过滤器"));
            pcap_freealldevs(alldev);
            return -1;
        }
    }

    //设置过滤器
    if (pcap_setfilter(adhandle, &fcode) < 0)
    {
        MessageBox(_T("设置过滤器错误"));
        pcap_freealldevs(alldev);
        return -1;
    }

    /* 设置数据包存储路径*/
    CFileFind file;
    char thistime[30];
    struct tm *ltime;
    memset(filepath, 0, 512);
    memset(filename, 0, 128);

    if (!file.FindFile(_T("SavedData")))
    {
        CreateDirectory(_T("SavedData"), NULL);
    }

    time_t nowtime;
    time(&nowtime);
    ltime = localtime(&nowtime);
    strftime(thistime, sizeof(thistime), "%Y%m%d %H%M%S", ltime);
    strcpy(filepath, "SavedData\\");
    strcat(filename, thistime);
    strcat(filename, ".pcap");

    strcat(filepath, filename);
    dumpfile = pcap_dump_open(adhandle, filepath);
    if (dumpfile == NULL)
    {
        MessageBox(_T("文件创建错误！"));
        return -1;
    }

    pcap_freealldevs(alldev);

    /*接收数据，新建线程处理*/
    LPDWORD threadCap = NULL;
    m_ThreadHandle = CreateThread(NULL, 0, CapThread, this, 0, threadCap);
    if (m_ThreadHandle == NULL)
    {
        int code = GetLastError();
        CString str;
        str.Format(_T("创建线程错误，错误码: %d."), code);
        MessageBox(str);
        return -1;
    }
    return 1;
}

DWORD WINAPI CapThread(LPVOID lpParameter)
{
    int res, nItem;
    struct tm *ltime;
    CString timestr, buf, srcMac, destMac;
    time_t local_tv_sec;
    struct pcap_pkthdr *header;									  //数据包头
    const u_char *pkt_data = NULL, *pData = NULL;     //网络中收到的字节流数据
    u_char *ppkt_data;

    CSnifferDlg *pthis = (CSnifferDlg*)lpParameter;
    if (pthis->m_ThreadHandle == NULL)
    {
        MessageBox(NULL, _T("线程句柄错误"), _T("提示"), MB_OK);
        return -1;
    }

    while ((res = pcap_next_ex(pthis->adhandle, &header, &pkt_data)) >= 0)
    {
        if (res == 0)				//超时
            continue;

        struct datapkt *data = (struct datapkt*)malloc(sizeof(struct datapkt));
        memset(data, 0, sizeof(struct datapkt));

        if (NULL == data)
        {
            MessageBox(NULL, _T("空间已满，无法接收新的数据包"), _T("Error"), MB_OK);
            return -1;
        }

        //分析出错或所接收数据包不在处理范围内
        if (analyze_frame(pkt_data, data, &(pthis->npacket)) < 0)
            continue;

        //将数据包保存到打开的文件中
        if (pthis->dumpfile != NULL)
        {
            pcap_dump((unsigned char*)pthis->dumpfile, header, pkt_data);
        }

        //更新各类数据包计数
        pthis->UpdateNPacket();

        //将本地化后的数据装入一个链表中，以便后来使用		
        ppkt_data = (u_char*)malloc(header->len);
        memcpy(ppkt_data, pkt_data, header->len);

        pthis->m_localDataList.AddTail(data);
        pthis->m_netDataList.AddTail(ppkt_data);

        /*预处理，获得时间、长度*/
        data->len = header->len;								//链路中收到的数据长度
        local_tv_sec = header->ts.tv_sec;
        ltime = localtime(&local_tv_sec);
        data->time[0] = ltime->tm_year + 1900;
        data->time[1] = ltime->tm_mon + 1;
        data->time[2] = ltime->tm_mday;
        data->time[3] = ltime->tm_hour;
        data->time[4] = ltime->tm_min;
        data->time[5] = ltime->tm_sec;

        /*为新接收到的数据包在listControl中新建一个item*/
        buf.Format(_T("%d"), pthis->npkt);
        nItem = pthis->m_listCtrl.InsertItem(pthis->npkt, buf);

        /*显示时间戳*/
        timestr.Format(_T("%d/%d/%d  %d:%d:%d"), data->time[0],
            data->time[1], data->time[2], data->time[3], data->time[4], data->time[5]);
        pthis->m_listCtrl.SetItemText(nItem, 1, timestr);
        //pthis->m_listCtrl.setitem

        /*显示长度*/
        buf.Empty();
        buf.Format(_T("%d"), data->len);
        pthis->m_listCtrl.SetItemText(nItem, 2, buf);

        /*显示源MAC*/
        buf.Empty();
        buf.Format(_T("%02X-%02X-%02X-%02X-%02X-%02X"), data->ethh->src[0], data->ethh->src[1],
            data->ethh->src[2], data->ethh->src[3], data->ethh->src[4], data->ethh->src[5]);
        pthis->m_listCtrl.SetItemText(nItem, 3, buf);

        /*显示目的MAC*/
        buf.Empty();
        buf.Format(_T("%02X-%02X-%02X-%02X-%02X-%02X"), data->ethh->dest[0], data->ethh->dest[1],
            data->ethh->dest[2], data->ethh->dest[3], data->ethh->dest[4], data->ethh->dest[5]);
        pthis->m_listCtrl.SetItemText(nItem, 4, buf);

        /*获得协议*/
        pthis->m_listCtrl.SetItemText(nItem, 5, CString(data->pktType));

        /*获得源IP*/
        buf.Empty();
        if (0x0806 == data->ethh->type)
        {
            buf.Format(_T("%d.%d.%d.%d"), data->arph->ar_srcip[0],
                data->arph->ar_srcip[1], data->arph->ar_srcip[2], data->arph->ar_srcip[3]);
        }
        else if (0x0800 == data->ethh->type) {
            struct  in_addr in;
            in.S_un.S_addr = data->iph->saddr;
            buf = CString(inet_ntoa(in));
        }
        else if (0x86dd == data->ethh->type) {
            int n;
            for (n = 0; n < 8; n++)
            {
                if (n <= 6)
                    buf.AppendFormat(_T("%02x:"), data->iph6->saddr[n]);
                else
                    buf.AppendFormat(_T("%02x"), data->iph6->saddr[n]);
            }
        }
        pthis->m_listCtrl.SetItemText(nItem, 6, buf);

        /*获得目的IP*/
        buf.Empty();
        if (0x0806 == data->ethh->type)
        {
            buf.Format(_T("%d.%d.%d.%d"), data->arph->ar_destip[0],
                data->arph->ar_destip[1], data->arph->ar_destip[2], data->arph->ar_destip[3]);
        }
        else if (0x0800 == data->ethh->type) {
            struct  in_addr in;
            in.S_un.S_addr = data->iph->daddr;
            buf = CString(inet_ntoa(in));
        }
        else if (0x86dd == data->ethh->type) {
            int n;
            for (n = 0; n < 8; n++)
            {
                if (n <= 6)
                    buf.AppendFormat(_T("%02x:"), data->iph6->daddr[n]);
                else
                    buf.AppendFormat(_T("%02x"), data->iph6->daddr[n]);
            }
        }
        pthis->m_listCtrl.SetItemText(nItem, 7, buf);

        /*对包计数*/
        pthis->npkt++;

    }
    return 1;
}

//更新信息
int CSnifferDlg::UpdateEdit(int index)
{
    POSITION localpos, netpos;
    localpos = this->m_localDataList.FindIndex(index);
    netpos = this->m_netDataList.FindIndex(index);

    struct datapkt* local_data = (struct datapkt*)(this->m_localDataList.GetAt(localpos));
    u_char * net_data = (u_char*)(this->m_netDataList.GetAt(netpos));

    CString buf;
    print_packet_hex(net_data, local_data->len, &buf);
    //this-
    this->m_edit.SetWindowText(buf);

    return 1;
}

//更新统计数据
int CSnifferDlg::UpdateNPacket()
{
    CString str_num;
    str_num.Format(_T("%d"), this->npacket.n_arp);
    this->m_editNArp.SetWindowText(str_num);

    str_num.Format(_T("%d"), this->npacket.n_http);
    this->m_editNHttp.SetWindowText(str_num);

    str_num.Format(_T("%d"), this->npacket.n_icmp);
    this->m_editNIcmp.SetWindowText(str_num);

    str_num.Format(_T("%d"), this->npacket.n_ip6);
    this->m_editNIp.SetWindowText(str_num);

    str_num.Format(_T("%d"), this->npacket.n_other);
    this->m_editNOther.SetWindowText(str_num);

    str_num.Format(_T("%d"), this->npacket.n_sum);
    this->m_editNSum.SetWindowText(str_num);

    str_num.Format(_T("%d"), this->npacket.n_tcp);
    this->m_editNTcp.SetWindowText(str_num);

    str_num.Format(_T("%d"), this->npacket.n_udp);
    this->m_editNUdp.SetWindowText(str_num);

    str_num.Format(_T("%d"), this->npacket.n_ip);
    this->m_editNIpv4.SetWindowText(str_num);

    str_num.Format(_T("%d"), this->npacket.n_icmp6);
    this->m_editIcmpv6.SetWindowText(str_num);

    return 1;
}

//更新树形控件
int CSnifferDlg::UpdateTree(int index)
{
    POSITION localpos;
    CString str;
    int i;

    this->m_treeCtrl.DeleteAllItems();

    localpos = this->m_localDataList.FindIndex(index);
    struct datapkt* local_data = (struct datapkt*)(this->m_localDataList.GetAt(localpos));

    HTREEITEM root = this->m_treeCtrl.GetRootItem();
    str.Format(_T("接收到的第%d个数据包"), index + 1);
    HTREEITEM data = this->m_treeCtrl.InsertItem(str, root);

    /*处理帧数据*/
    HTREEITEM frame = this->m_treeCtrl.InsertItem(_T("链路层数据"), data);
    //源MAC
    str.Format(_T("源MAC："));
    for (i = 0; i < 6; i++)
    {
        if (i <= 4)
            str.AppendFormat(_T("%02x-"), local_data->ethh->src[i]);
        else
            str.AppendFormat(_T("%02x"), local_data->ethh->src[i]);
    }
    this->m_treeCtrl.InsertItem(str, frame);
    //目的MAC
    str.Format(_T("目的MAC："));
    for (i = 0; i < 6; i++)
    {
        if (i <= 4)
            str.AppendFormat(_T("%02x-"), local_data->ethh->dest[i]);
        else
            str.AppendFormat(_T("%02x"), local_data->ethh->dest[i]);
    }
    this->m_treeCtrl.InsertItem(str, frame);
    //类型
    str.Format(_T("类型：0x%02x"), local_data->ethh->type);
    this->m_treeCtrl.InsertItem(str, frame);

    /*处理IP、ARP、IPv6数据包*/
    if (0x0806 == local_data->ethh->type)	//ARP
    {
        HTREEITEM arp = this->m_treeCtrl.InsertItem(_T("ARP协议头"), data);
        str.Format(_T("硬件类型：%d"), local_data->arph->ar_hrd);
        this->m_treeCtrl.InsertItem(str, arp);
        str.Format(_T("协议类型：0x%02x"), local_data->arph->ar_pro);
        this->m_treeCtrl.InsertItem(str, arp);
        str.Format(_T("硬件地址长度：%d"), local_data->arph->ar_hln);
        this->m_treeCtrl.InsertItem(str, arp);
        str.Format(_T("协议地址长度：%d"), local_data->arph->ar_pln);
        this->m_treeCtrl.InsertItem(str, arp);
        str.Format(_T("操作码：%d"), local_data->arph->ar_op);
        this->m_treeCtrl.InsertItem(str, arp);

        str.Format(_T("发送方MAC："));
        for (i = 0; i < 6; i++)
        {
            if (i <= 4)
                str.AppendFormat(_T("%02x-"), local_data->arph->ar_srcmac[i]);
            else
                str.AppendFormat(_T("%02x"), local_data->arph->ar_srcmac[i]);
        }
        this->m_treeCtrl.InsertItem(str, arp);

        str.Format(_T("发送方IP："), local_data->arph->ar_hln);
        for (i = 0; i < 4; i++)
        {
            if (i <= 2)
                str.AppendFormat(_T("%d."), local_data->arph->ar_srcip[i]);
            else
                str.AppendFormat(_T("%d"), local_data->arph->ar_srcip[i]);
        }
        this->m_treeCtrl.InsertItem(str, arp);

        str.Format(_T("接收方MAC："), local_data->arph->ar_hln);
        for (i = 0; i < 6; i++)
        {
            if (i <= 4)
                str.AppendFormat(_T("%02x-"), local_data->arph->ar_destmac[i]);
            else
                str.AppendFormat(_T("%02x"), local_data->arph->ar_destmac[i]);
        }
        this->m_treeCtrl.InsertItem(str, arp);

        str.Format(_T("接收方IP："), local_data->arph->ar_hln);
        for (i = 0; i < 4; i++)
        {
            if (i <= 2)
                str.AppendFormat(_T("%d."), local_data->arph->ar_destip[i]);
            else
                str.AppendFormat(_T("%d"), local_data->arph->ar_destip[i]);
        }
        this->m_treeCtrl.InsertItem(str, arp);

    }
    else if (0x0800 == local_data->ethh->type) { //IP

        HTREEITEM ip = this->m_treeCtrl.InsertItem(_T("IP协议头"), data);

        str.Format(_T("版本：%d"), local_data->iph->version);
        this->m_treeCtrl.InsertItem(str, ip);
        str.Format(_T("IP头长：%d"), local_data->iph->ihl);
        this->m_treeCtrl.InsertItem(str, ip);
        str.Format(_T("服务类型：%d"), local_data->iph->tos);
        this->m_treeCtrl.InsertItem(str, ip);
        str.Format(_T("总长度：%d"), local_data->iph->tlen);
        this->m_treeCtrl.InsertItem(str, ip);
        str.Format(_T("标识：0x%02x"), local_data->iph->id);
        this->m_treeCtrl.InsertItem(str, ip);
        str.Format(_T("段偏移：%d"), local_data->iph->frag_off);
        this->m_treeCtrl.InsertItem(str, ip);
        str.Format(_T("生存期：%d"), local_data->iph->ttl);
        this->m_treeCtrl.InsertItem(str, ip);
        str.Format(_T("协议：%d"), local_data->iph->proto);
        this->m_treeCtrl.InsertItem(str, ip);
        str.Format(_T("头部校验和：0x%02x"), local_data->iph->check);
        this->m_treeCtrl.InsertItem(str, ip);

        str.Format(_T("源IP："));
        struct in_addr in;
        in.S_un.S_addr = local_data->iph->saddr;
        str.AppendFormat(CString(inet_ntoa(in)));
        this->m_treeCtrl.InsertItem(str, ip);

        str.Format(_T("目的IP："));
        in.S_un.S_addr = local_data->iph->daddr;
        str.AppendFormat(CString(inet_ntoa(in)));
        this->m_treeCtrl.InsertItem(str, ip);

        /*处理传输层ICMP、UDP、TCP*/
        if (1 == local_data->iph->proto)	//ICMP
        {
            HTREEITEM icmp = this->m_treeCtrl.InsertItem(_T("ICMP协议头"), data);

            str.Format(_T("类型:%d"), local_data->icmph->type);
            this->m_treeCtrl.InsertItem(str, icmp);
            str.Format(_T("代码:%d"), local_data->icmph->code);
            this->m_treeCtrl.InsertItem(str, icmp);
            str.Format(_T("序号:%d"), local_data->icmph->seq);
            this->m_treeCtrl.InsertItem(str, icmp);
            str.Format(_T("校验和:%d"), local_data->icmph->chksum);
            this->m_treeCtrl.InsertItem(str, icmp);

        }
        else if (6 == local_data->iph->proto) {				//TCP

            HTREEITEM tcp = this->m_treeCtrl.InsertItem(_T("TCP协议头"), data);

            str.Format(_T("  源端口:%d"), local_data->tcph->sport);
            this->m_treeCtrl.InsertItem(str, tcp);
            str.Format(_T("  目的端口:%d"), local_data->tcph->dport);
            this->m_treeCtrl.InsertItem(str, tcp);
            str.Format(_T("  序列号:0x%02x"), local_data->tcph->seq);
            this->m_treeCtrl.InsertItem(str, tcp);
            str.Format(_T("  确认号:%d"), local_data->tcph->ack_seq);
            this->m_treeCtrl.InsertItem(str, tcp);
            str.Format(_T("  头部长度:%d"), local_data->tcph->doff);

            HTREEITEM flag = this->m_treeCtrl.InsertItem(_T(" +标志位"), tcp);

            str.Format(_T("CWR %d"), local_data->tcph->cwr);
            this->m_treeCtrl.InsertItem(str, flag);
            str.Format(_T("ECE %d"), local_data->tcph->ece);
            this->m_treeCtrl.InsertItem(str, flag);
            str.Format(_T("URG %d"), local_data->tcph->urg);
            this->m_treeCtrl.InsertItem(str, flag);
            str.Format(_T("ACK %d"), local_data->tcph->ack);
            this->m_treeCtrl.InsertItem(str, flag);
            str.Format(_T("PSH %d"), local_data->tcph->psh);
            this->m_treeCtrl.InsertItem(str, flag);
            str.Format(_T("RST %d"), local_data->tcph->rst);
            this->m_treeCtrl.InsertItem(str, flag);
            str.Format(_T("SYN %d"), local_data->tcph->syn);
            this->m_treeCtrl.InsertItem(str, flag);
            str.Format(_T("FIN %d"), local_data->tcph->fin);
            this->m_treeCtrl.InsertItem(str, flag);

            str.Format(_T("  紧急指针:%d"), local_data->tcph->urg_ptr);
            this->m_treeCtrl.InsertItem(str, tcp);
            str.Format(_T("  校验和:0x%02x"), local_data->tcph->check);
            this->m_treeCtrl.InsertItem(str, tcp);
            str.Format(_T("  选项:%d"), local_data->tcph->opt);
            this->m_treeCtrl.InsertItem(str, tcp);
        }
        else if (17 == local_data->iph->proto) {				//UDP
            HTREEITEM udp = this->m_treeCtrl.InsertItem(_T("UDP协议头"), data);

            str.Format(_T("源端口:%d"), local_data->udph->sport);
            this->m_treeCtrl.InsertItem(str, udp);
            str.Format(_T("目的端口:%d"), local_data->udph->dport);
            this->m_treeCtrl.InsertItem(str, udp);
            str.Format(_T("总长度:%d"), local_data->udph->len);
            this->m_treeCtrl.InsertItem(str, udp);
            str.Format(_T("校验和:0x%02x"), local_data->udph->check);
            this->m_treeCtrl.InsertItem(str, udp);
        }
    }
    else if (0x86dd == local_data->ethh->type) {		//IPv6
        HTREEITEM ip6 = this->m_treeCtrl.InsertItem(_T("IPv6协议头"), data);

        str.Format(_T("版本:%d"), local_data->iph6->flowtype);
        this->m_treeCtrl.InsertItem(str, ip6);
        str.Format(_T("流类型:%d"), local_data->iph6->version);
        this->m_treeCtrl.InsertItem(str, ip6);

        str.Format(_T("流标签:%d"), local_data->iph6->flowid);
        this->m_treeCtrl.InsertItem(str, ip6);
        str.Format(_T("有效载荷长度:%d"), local_data->iph6->plen);
        this->m_treeCtrl.InsertItem(str, ip6);
        str.Format(_T("下一个首部:0x%02x"), local_data->iph6->nh);
        this->m_treeCtrl.InsertItem(str, ip6);
        str.Format(_T("跳限制:%d"), local_data->iph6->hlim);
        this->m_treeCtrl.InsertItem(str, ip6);

        str.Format(_T("源地址:"));
        int n;
        for (n = 0; n < 8; n++)
        {
            if (n <= 6)
                str.AppendFormat(_T("%02x:"), local_data->iph6->saddr[n]);
            else
                str.AppendFormat(_T("%02x"), local_data->iph6->saddr[n]);
        }
        this->m_treeCtrl.InsertItem(str, ip6);

        str.Format(_T("目的地址:"));
        for (n = 0; n < 8; n++)
        {
            if (n <= 6)
                str.AppendFormat(_T("%02x:"), local_data->iph6->saddr[n]);
            else
                str.AppendFormat(_T("%02x"), local_data->iph6->saddr[n]);
        }
        this->m_treeCtrl.InsertItem(str, ip6);

        /*处理传输层ICMPv6、UDP、TCP*/
        if (0x3a == local_data->iph6->nh) //ICMPv6
        {
            HTREEITEM icmp6 = this->m_treeCtrl.InsertItem(_T("ICMPv6协议头"), data);

            str.Format(_T("类型:%d"), local_data->icmph6->type);
            this->m_treeCtrl.InsertItem(str, icmp6);
            str.Format(_T("代码:%d"), local_data->icmph6->code);
            this->m_treeCtrl.InsertItem(str, icmp6);
            str.Format(_T("序号:%d"), local_data->icmph6->seq);
            this->m_treeCtrl.InsertItem(str, icmp6);
            str.Format(_T("校验和:%d"), local_data->icmph6->chksum);
            this->m_treeCtrl.InsertItem(str, icmp6);
            str.Format(_T("选项-类型:%d"), local_data->icmph6->op_type);
            this->m_treeCtrl.InsertItem(str, icmp6);
            str.Format(_T("选项-长度%d"), local_data->icmph6->op_len);
            this->m_treeCtrl.InsertItem(str, icmp6);
            str.Format(_T("选项-链路层地址:"));
            int i;
            for (i = 0; i < 6; i++)
            {
                if (i <= 4)
                    str.AppendFormat(_T("%02x-"), local_data->icmph6->op_ethaddr[i]);
                else
                    str.AppendFormat(_T("%02x"), local_data->icmph6->op_ethaddr[i]);
            }
            this->m_treeCtrl.InsertItem(str, icmp6);

        }
        else if (0x06 == local_data->iph6->nh) {				//TCP

            HTREEITEM tcp = this->m_treeCtrl.InsertItem(_T("TCP协议头"), data);

            str.Format(_T("  源端口:%d"), local_data->tcph->sport);
            this->m_treeCtrl.InsertItem(str, tcp);
            str.Format(_T("  目的端口:%d"), local_data->tcph->dport);
            this->m_treeCtrl.InsertItem(str, tcp);
            str.Format(_T("  序列号:0x%02x"), local_data->tcph->seq);
            this->m_treeCtrl.InsertItem(str, tcp);
            str.Format(_T("  确认号:%d"), local_data->tcph->ack_seq);
            this->m_treeCtrl.InsertItem(str, tcp);
            str.Format(_T("  头部长度:%d"), local_data->tcph->doff);

            HTREEITEM flag = this->m_treeCtrl.InsertItem(_T("标志位"), tcp);

            str.Format(_T("CWR %d"), local_data->tcph->cwr);
            this->m_treeCtrl.InsertItem(str, flag);
            str.Format(_T("ECE %d"), local_data->tcph->ece);
            this->m_treeCtrl.InsertItem(str, flag);
            str.Format(_T("URG %d"), local_data->tcph->urg);
            this->m_treeCtrl.InsertItem(str, flag);
            str.Format(_T("ACK %d"), local_data->tcph->ack);
            this->m_treeCtrl.InsertItem(str, flag);
            str.Format(_T("PSH %d"), local_data->tcph->psh);
            this->m_treeCtrl.InsertItem(str, flag);
            str.Format(_T("RST %d"), local_data->tcph->rst);
            this->m_treeCtrl.InsertItem(str, flag);
            str.Format(_T("SYN %d"), local_data->tcph->syn);
            this->m_treeCtrl.InsertItem(str, flag);
            str.Format(_T("FIN %d"), local_data->tcph->fin);
            this->m_treeCtrl.InsertItem(str, flag);

            str.Format(_T("  紧急指针:%d"), local_data->tcph->urg_ptr);
            this->m_treeCtrl.InsertItem(str, tcp);
            str.Format(_T("  校验和:0x%02x"), local_data->tcph->check);
            this->m_treeCtrl.InsertItem(str, tcp);
            str.Format(_T("  选项:%d"), local_data->tcph->opt);
            this->m_treeCtrl.InsertItem(str, tcp);
        }
        else if (0x11 == local_data->iph6->nh) {				//UDP
            HTREEITEM udp = this->m_treeCtrl.InsertItem(_T("UDP协议头"), data);

            str.Format(_T("源端口:%d"), local_data->udph->sport);
            this->m_treeCtrl.InsertItem(str, udp);
            str.Format(_T("目的端口:%d"), local_data->udph->dport);
            this->m_treeCtrl.InsertItem(str, udp);
            str.Format(_T("总长度:%d"), local_data->udph->len);
            this->m_treeCtrl.InsertItem(str, udp);
            str.Format(_T("校验和:0x%02x"), local_data->udph->check);
            this->m_treeCtrl.InsertItem(str, udp);
        }
    }

    return 1;
}


int CSnifferDlg::SaveFile()
{
    CFileFind find;
    if (NULL == find.FindFile(CString(filepath)))
    {
        MessageBox(_T("保存文件遇到未知意外"));
        return -1;
    }

    //打开文件对话框
    CFileDialog FileDlg(FALSE, _T(".pcap"), NULL, OFN_HIDEREADONLY | OFN_OVERWRITEPROMPT);
    FileDlg.m_ofn.lpstrInitialDir = _T("c:\\");
    if (FileDlg.DoModal() == IDOK)
    {
        CopyFile(CString(filepath), FileDlg.GetPathName(), TRUE);
    }
    return 1;
}

int CSnifferDlg::ReadFile(CString path)
{
    int res, nItem, i;
    struct tm *ltime;
    CString timestr, buf, srcMac, destMac;
    time_t local_tv_sec;
    struct pcap_pkthdr *header;			//数据包头
    const u_char *pkt_data = NULL;      //网络中收到的字节流数据
    u_char *ppkt_data;

    CSnifferDlg *pthis = this;		    //一些代码从CapThread修改，为节约工作量，故保留pthis指针
    pcap_t *fp;

    //首先处理一下路径，利用pcap_open_offline打开文件时，
    //路径需要用char *类型，不能用CString强制转换后的char *
    int len = path.GetLength() + 1;		//注意这一个细节，必须要加1，否则会出错
    char* charpath = (char *)malloc(len);
    memset(charpath, 0, len);
    if (NULL == charpath)
        return -1;

    for (i = 0; i < len; i++)
        charpath[i] = (char)path.GetAt(i);

    //打开相关文件
    if ((fp = pcap_open_offline(charpath, errbuf)) == NULL)
    {
        MessageBox(_T("打开文件错误") + CString(errbuf));
        return -1;
    }

    while ((res = pcap_next_ex(fp, &header, &pkt_data)) >= 0)
    {
        struct datapkt *data = (struct datapkt*)malloc(sizeof(struct datapkt));
        memset(data, 0, sizeof(struct datapkt));

        if (NULL == data)
        {
            MessageBox(_T("空间已满，无法接收新的数据包"));
            return  -1;
        }

        //分析出错或所接收数据包不在处理范围内
        if (analyze_frame(pkt_data, data, &(pthis->npacket)) < 0)
            continue;

        //更新各类数据包计数
        pthis->UpdateNPacket();

        //将本地化后的数据装入一个链表中，以便后来使用		
        ppkt_data = (u_char*)malloc(header->len);
        memcpy(ppkt_data, pkt_data, header->len);

        pthis->m_localDataList.AddTail(data);
        pthis->m_netDataList.AddTail(ppkt_data);

        /*预处理，获得时间、长度*/
        data->len = header->len;            //链路中收到的数据长度
        local_tv_sec = header->ts.tv_sec;
        ltime = localtime(&local_tv_sec);
        data->time[0] = ltime->tm_year + 1900;
        data->time[1] = ltime->tm_mon + 1;
        data->time[2] = ltime->tm_mday;
        data->time[3] = ltime->tm_hour;
        data->time[4] = ltime->tm_min;
        data->time[5] = ltime->tm_sec;

        /*为新接收到的数据包在listControl中新建一个item*/
        buf.Format(_T("%d"), pthis->npkt);
        nItem = pthis->m_listCtrl.InsertItem(pthis->npkt, buf);

        /*显示时间戳*/
        timestr.Format(_T("%d/%d/%d  %d:%d:%d"), data->time[0],
            data->time[1], data->time[2], data->time[3], data->time[4], data->time[5]);
        pthis->m_listCtrl.SetItemText(nItem, 1, timestr);

        /*显示长度*/
        buf.Empty();
        buf.Format(_T("%d"), data->len);
        pthis->m_listCtrl.SetItemText(nItem, 2, buf);

        /*显示源MAC*/
        buf.Empty();
        buf.Format(_T("%02X-%02X-%02X-%02X-%02X-%02X"), data->ethh->src[0], data->ethh->src[1],
            data->ethh->src[2], data->ethh->src[3], data->ethh->src[4], data->ethh->src[5]);
        pthis->m_listCtrl.SetItemText(nItem, 3, buf);

        /*显示目的MAC*/
        buf.Empty();
        buf.Format(_T("%02X-%02X-%02X-%02X-%02X-%02X"), data->ethh->dest[0], data->ethh->dest[1],
            data->ethh->dest[2], data->ethh->dest[3], data->ethh->dest[4], data->ethh->dest[5]);
        pthis->m_listCtrl.SetItemText(nItem, 4, buf);

        /*获得协议*/
        pthis->m_listCtrl.SetItemText(nItem, 5, CString(data->pktType));

        /*获得源IP*/
        buf.Empty();
        if (0x0806 == data->ethh->type)
        {
            buf.Format(_T("%d.%d.%d.%d"), data->arph->ar_srcip[0],
                data->arph->ar_srcip[1], data->arph->ar_srcip[2], data->arph->ar_srcip[3]);
        }
        else  if (0x0800 == data->ethh->type) {
            struct  in_addr in;
            in.S_un.S_addr = data->iph->saddr;
            buf = CString(inet_ntoa(in));
        }
        else if (0x86dd == data->ethh->type) {
            int i;
            for (i = 0; i < 8; i++)
            {
                if (i <= 6)
                    buf.AppendFormat(_T("%02x-"), data->iph6->saddr[i]);
                else
                    buf.AppendFormat(_T("%02x"), data->iph6->saddr[i]);
            }
        }
        pthis->m_listCtrl.SetItemText(nItem, 6, buf);

        /*获得目的IP*/
        buf.Empty();
        if (0x0806 == data->ethh->type)
        {
            buf.Format(_T("%d.%d.%d.%d"), data->arph->ar_destip[0],
                data->arph->ar_destip[1], data->arph->ar_destip[2], data->arph->ar_destip[3]);
        }
        else if (0x0800 == data->ethh->type) {
            struct  in_addr in;
            in.S_un.S_addr = data->iph->daddr;
            buf = CString(inet_ntoa(in));
        }
        else if (0x86dd == data->ethh->type) {
            int i;
            for (i = 0; i < 8; i++)
            {
                if (i <= 6)

                    buf.AppendFormat(_T("%02x-"), data->iph6->daddr[i]);
                else
                    buf.AppendFormat(_T("%02x"), data->iph6->daddr[i]);
            }
        }
        pthis->m_listCtrl.SetItemText(nItem, 7, buf);

        /*对包计数*/
        pthis->npkt++;
    }
    pcap_close(fp);

    return 1;
}
