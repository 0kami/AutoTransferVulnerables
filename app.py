#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Created by wh1t3P1g at 2016/11/17

from api import *

class App:
    def __init__(self,res):
        self.proxy=res['proxy']
        self.num=res['num']
        self.date=res['date']

    def run(self):
        LOG.pprint("+", "start program...", GREEN)
        LOG.pprint("+", "fetching vul list...", GREEN)
        # 获取漏洞列表
        vuls=self.getVuls()
        self.store(vuls)
        LOG.pprint("+", "fecthing vul details...", GREEN)
        # 获取对应列表的漏洞详情
        results=self.getDetail(vuls)
        if results == []:
            LOG.pprint("+", "nothing to transfer...", GREEN)
            LOG.pprint("+", "done", GREEN)
            sys.exit(0)
        # print results
        LOG.pprint("+", "start transfer...", GREEN)
        res=self.getTransfer(results)
        # print res
        LOG.pprint("+", "transfer done...", GREEN)
        LOG.pprint("+", "output file to " + VULDB, GREEN)
        # 生成文件
        self.output(res,results)
        LOG.pprint("+", "done", GREEN)



    def getVuls(self):
        sf = FetchVulInSF()
        vuls = []
        if self.num:
            vuls = sf.fetchLine(self.num, proxy=self.proxy)
        elif self.date:
            vuls = sf.fetch(self.date, proxy=self.proxy)
        return vuls

    def getDetail(self,vuls):
        fc = FetchContentSF(vuls, proxy=self.proxy)
        results = fc.fetch()
        results = [temp for temp in results if temp != None]
        if results == []:
            LOG.pprint("+", "nothing to transfer...", GREEN)
            LOG.pprint("+", "done", GREEN)
            sys.exit(0)
        return results

    def getTransfer(self,results):
        tv = TransferVuls(results)
        res = tv.dealWithSF()
        return res

    def output(self,res,results):
        oftt = OutputFileToTxt(res)
        oftt.output()
        LOG.pprint("+", "log CVE db done...", GREEN)
        LOG.pprint("+", "output vul excel...", GREEN)
        test = OutputFileToExcel(results)
        test.output()

    def store(self,vuls):
        with open("./url.db", 'a+') as f:
            for line in vuls:
                f.write(line + "\n")