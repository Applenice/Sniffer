#include "stdafx.h"
#include "Sniffer.h"
#include "SnifferDlg.h"
#include "afxdialogex.h"
#include "resource.h"


//��ʼ��ť
void CSnifferDlg::OnBnClickedButton1()
{
    // TODO: �ڴ���ӿؼ�֪ͨ����������
    //����Ѿ��������ˣ���ʾ��������
    if (this->m_localDataList.IsEmpty() == FALSE)
    {
        if (MessageBox(_T("ȷ�Ϸ����������ݣ�"), _T("����"), MB_YESNO) == IDNO)
        {
            this->SaveFile();
        }
    }

    this->npkt = 1;									//���¼���
    this->m_localDataList.RemoveAll();				//ÿ��һ��ʼ�ͽ���ǰ���������յ�
    this->m_netDataList.RemoveAll();
    memset(&(this->npacket), 0, sizeof(struct pktcount));
    this->UpdateNPacket();

    if (this->StartCap() < 0)
        return;
    this->m_listCtrl.DeleteAllItems();
    this->m_treeCtrl.DeleteAllItems();
    this->m_edit.SetWindowTextW(_T(""));
    this->m_buttonStart.EnableWindow(FALSE);
    this->m_buttonStop.EnableWindow(TRUE);
    this->m_buttonSave.EnableWindow(FALSE);
}

//������ť
void CSnifferDlg::OnBnClickedButton2()
{
    // TODO: �ڴ���ӿؼ�֪ͨ����������
    if (NULL == this->m_ThreadHandle)
        return;
    if (TerminateThread(this->m_ThreadHandle, -1) == 0)
    {
        MessageBox(_T("�ر��̴߳������Ժ�����"));
        return;
    }
    this->m_ThreadHandle = NULL;
    this->m_buttonStart.EnableWindow(TRUE);
    this->m_buttonStop.EnableWindow(FALSE);
    this->m_buttonSave.EnableWindow(TRUE);
}

//�б�
void CSnifferDlg::OnLvnItemchangedList1(NMHDR *pNMHDR, LRESULT *pResult)
{
    LPNMLISTVIEW pNMLV = reinterpret_cast<LPNMLISTVIEW>(pNMHDR);
    // TODO: �ڴ���ӿؼ�֪ͨ����������
    int index;
    index = this->m_listCtrl.GetHotItem();

    if (index > this->m_localDataList.GetCount() - 1)
        return;

    this->UpdateEdit(index);
    this->UpdateTree(index);
    *pResult = 0;
}

//���水ť
void CSnifferDlg::OnBnClickedButton3()
{
    // TODO: �ڴ���ӿؼ�֪ͨ����������
    if (this->SaveFile() < 0)
        return;
}

//��ȡ��ť
void CSnifferDlg::OnBnClickedButton4()
{
    // TODO: �ڴ���ӿؼ�֪ͨ����������

    /*�������������ѡ���쳣���������ն����õ�������*/
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

    //���ļ��Ի���
    CFileDialog FileDlg(TRUE, _T(".pcap"), NULL, OFN_HIDEREADONLY | OFN_OVERWRITEPROMPT);
    FileDlg.m_ofn.lpstrInitialDir = _T("c:\\");
    if (FileDlg.DoModal() == IDOK)
    {
        int ret = this->ReadFile(FileDlg.GetPathName());
        if (ret < 0)
            return;
    }
}

//�ı�ListCtrlÿ����ɫ
void CSnifferDlg::OnNMCustomdrawList1(NMHDR *pNMHDR, LRESULT *pResult)
{
    //LPNMCUSTOMDRAW pNMCD = reinterpret_cast<LPNMCUSTOMDRAW>(pNMHDR);
    LPNMLVCUSTOMDRAW pNMCD = (LPNMLVCUSTOMDRAW)pNMHDR;
    *pResult = 0;
    // TODO: �ڴ���ӿؼ�֪ͨ����������
    if (CDDS_PREPAINT == pNMCD->nmcd.dwDrawStage)
    {
        *pResult = CDRF_NOTIFYITEMDRAW;
    }
    else if (CDDS_ITEMPREPAINT == pNMCD->nmcd.dwDrawStage) {
        COLORREF crText;
        char buf[10];
        memset(buf, 0, 10);
        POSITION pos = this->m_localDataList.FindIndex(pNMCD->nmcd.dwItemSpec);
        struct datapkt * local_data = (struct datapkt *)this->m_localDataList.GetAt(pos);
        strcpy(buf, local_data->pktType);

        if (strcmp(buf, "IPV6") == 0)
            crText = RGB(111, 224, 254);
        else if (strcmp(buf, "UDP") == 0)
            crText = RGB(194, 195, 252);
        else if (strcmp(buf, "TCP") == 0)
            crText = RGB(230, 230, 230);
        else if (strcmp(buf, "ARP") == 0)
            crText = RGB(226, 238, 227);
        else if (strcmp(buf, "ICMP") == 0)
            crText = RGB(49, 164, 238);
        else if (strcmp(buf, "HTTP") == 0)
            crText = RGB(238, 232, 180);
        else if (strcmp(buf, "ICMPv6") == 0)
            crText = RGB(189, 254, 76);

        pNMCD->clrTextBk = crText;
        *pResult = CDRF_DODEFAULT;
    }
}
