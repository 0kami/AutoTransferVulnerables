#!/usr/bin/env python
# -*- coding: utf-8 -*-
# __author__ = 'gmfork'

from Transfer import TransferByYouDao
from multiprocessing.pool import ThreadPool
import time
from xlwt import *
from Config import VULDB,ROOT


class OutputFileToExcel:
    '''
    将获取到的文件翻译后生成excel
    '''
    def __init__(self,vuls):
        self.vuls = [vul for vul in vuls if vul]
        self.trans=TransferByYouDao()

    def output(self):
        try:
            if self.vuls != []:
                w = Workbook(encoding='utf-8')
                ws = w.add_sheet('漏洞清单')
                # 设置标题
                ws.write(0, 0, "漏洞名称")  #
                ws.write(0, 1, "CVE编号")  #
                ws.write(0, 2, "Bugraq ID")
                ws.write(0, 3, "类型")  #
                ws.write(0, 4, "存在漏洞的系统或软件")  #
                ws.write(0, 5, "危险等级")  #
                ws.write(0, 6, "最早公开时间")  #
                ws.write(0, 7, "漏洞起因")  #
                ws.write(0, 8, "可能发生的攻击或危害")
                ws.write(0, 9, "是否出现公开的攻击代码")
                ws.write(0, 10, "活跃程度")
                ws.write(0, 11, "安全建议")#
                ws.write(0, 12, "是否验证")#
                ws.write(0, 13, "涉及行业范围")
                ws.write(0, 14, "原始信息来源")#
                ws.write(0, 15, "发布范围")#
                # 填充数据
                t=1
                for line in self.vuls:
                    times=time.strptime(line['Published'],"%b %d %Y %H:%M%p")

                    date='.'.join([str(times.tm_year),str(times.tm_mon),str(times.tm_mday)])
                    ws.write(t,0,line['ch_title'])
                    ws.write(t,1,line['CVE'])
                    ws.write(t,3,line['ch_Class'])
                    if len(line['Vulnerable'])>32767:
                        ws.write(t, 4, "数据太长，请查看CVE漏洞库，复制受影响软件")
                    else:
                        ws.write(t,4,line['Vulnerable'])
                    ws.write(t, 5, '')
                    ws.write(t, 6, date)
                    if len(line['ch_discuss']) > 32767:
                        ws.write(t, 7, "数据太长，请查看CVE漏洞库，复制漏洞起因")
                    else:
                        ws.write(t, 7, line['ch_discuss'])

                    if len(line['ch_solution']) > 32767:
                        ws.write(t, 11, "数据太长，请查看CVE漏洞库，复制解决方案")
                    else:
                        ws.write(t, 11, line['ch_solution'])

                    ws.write(t, 12, '否')
                    ws.write(t, 14, line['references'])
                    ws.write(t, 15, "")
                    t+=1
                w.save(ROOT + '/vulList.xls')
        except:
            print '=== STEP ERROR INFO START'
            import traceback
            traceback.print_exc()
            print '=== STEP ERROR INFO END'
            w.save(ROOT + '/vulList.xls')
    def outfileNew(self):
        try:
            if self.vuls != []:
                w = Workbook(encoding='utf-8')
                ws = w.add_sheet('漏洞清单')
                # 设置标题
                ws.write(0, 0, "漏洞名称")  #
                ws.write(0, 1, "漏洞中文描述")  #
                ws.write(0, 2, "CVE编号")
                ws.write(0, 3, "CVE链接")  #
                ws.write(0, 4, "Bugraq ID")  #
                ws.write(0, 5, "漏洞影响对象类型")  #
                ws.write(0, 6, "厂商")  #
                ws.write(0, 7, "产品")  #
                ws.write(0, 8, "版本号")
                ws.write(0, 9, "危险等级")
                ws.write(0, 10, "最早公开时间")
                ws.write(0, 11, "漏洞技术成因")#
                ws.write(0, 12, "攻击及危害")#
                ws.write(0, 13, "是否出现验证利用攻击代码")
                ws.write(0, 14, "安全建议")#
                ws.write(0, 15, "原始信息来源")#
                # 填充数据
                t=1
                for line in self.vuls:
                    times=time.strptime(line['Published'],"%b %d %Y %H:%M%p")

                    date='-'.join([str(times.tm_year),str(times.tm_mon),str(times.tm_mday)])
                    # ws.write(t,0,line['ch_title'])# 漏洞名称中文
                    ws.write(t,0,line['title'])# 漏洞名称英文

                    #漏洞起因
                    if len(line['discuss']) > 32767:
                        ws.write(t, 1, "数据太长，请查看CVE漏洞库，复制漏洞起因")
                    else:
                        ws.write(t, 1, line['discuss'])
                    #CVE编号
                    ws.write(t,2,line['CVE'])
                    #CVE链接 选填 3
                    #Bugraq ID 选填 4
                    #漏洞影响对象类型 必填 5
                    #todo
                    #厂商 必填 6
                    ws.write(t,6,line['company'])
                    #产品 必填 与厂商相同 7
                    ws.write(t, 7, line['product'])
                    #版本号 8
                    if len(line['Vulnerable'])>32767:
                        ws.write(t, 8, "数据太长，请查看CVE漏洞库，复制受影响软件")
                    else:
                        ws.write(t,8,line['Vulnerable'])
                    #危险等级 必填 人工判断 9
                    #最早公开时间 必填 10
                    ws.write(t, 10, date)
                    #漏洞技术成因 11
                    ws.write(t,11,line['ch_Class'])
                    #攻击及危害 必填 12
                    #todo
                    #是否出现验证利用攻击代码 必填 可通过exploit tab下的信息判断 13
                    ws.write(t,13,line['isexploit'])
                    #安全建议 必填 14
                    if len(line['ch_solution']) > 32767:
                        ws.write(t, 14, "数据太长，请查看CVE漏洞库，复制解决方案")
                    else:
                        ws.write(t, 14, line['ch_solution'])
                    #原始信息来源 必填 15
                    ws.write(t, 15, line['references'])
                    t+=1
                w.save(ROOT + '/vulList.xls')
        except:
            print '=== STEP ERROR INFO START'
            import traceback
            traceback.print_exc()
            print '=== STEP ERROR INFO END'
            w.save(ROOT + '/vulList.xls')


class OutputFileToTxt:
    '''
    将获取到的文件翻译后生成txt
    '''
    def __init__(self,vuls):
        self.vuls=[vul for vul in vuls if vul]
        self.size=5
        self.trans=TransferByYouDao()

    def setThreadSize(self,size):
        self.size=size

    def output(self):
        try:
            if self.vuls!=[]:
                pool=ThreadPool(self.size)
                pool.map(self.toTxt,self.vuls)
                pool.close()
                pool.join()
        except:
            print '=== STEP ERROR INFO START'
            import traceback
            traceback.print_exc()
            print '=== STEP ERROR INFO END'

    def toTxt(self,line):
        # print "new files"
        pre="Title:{title}\r\n" \
            "Class:{Class}\r\n" \
            "CVE:{CVE}\r\n" \
            "Published:{Published}\r\n" \
            "Vulnerable:{Vulnerable}\r\n" \
            "discuss:{discuss}\r\n" \
            "exploit:{exploit}\r\n" \
            "solution:{solution}\r\n" \
            "references:{references}\r\n\r\n" \
            "ch_title:{ch_title}\r\n" \
            "ch_Class:{ch_Class}\r\n" \
            "ch_discuss:{ch_discuss}\r\n" \
            "ch_exploit:{ch_exploit}\r\n" \
            "ch_solution:{ch_solution}\r\n\r\n" \
            "url:{url}\r\n"

        with open(VULDB+line['CVE']+".txt",'wb') as f:
            res=pre.format(title=line['title'],
                           Class=line['Class'],
                           CVE=line['CVE'],
                           Published=line['Published'],
                           Vulnerable=line['Vulnerable'],
                           discuss=line['discuss'],
                           exploit=line['exploit'],
                           solution=line['solution'],
                           references=line['references'],
                           ch_title=line['ch_title'],
                           ch_Class=line['ch_Class'],
                           ch_discuss=line['ch_discuss'],
                           ch_exploit=line['ch_exploit'],
                           ch_solution=line['ch_solution'],
                           url=line['url'])
            f.write(res)


