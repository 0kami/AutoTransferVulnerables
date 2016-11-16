#!/usr/bin/python
# -*- coding: utf-8 -*-
# __author__ = 'gmfork'


from api import *
import argparse



def store(vuls):
    with open("./url.db",'a+') as f:
        for line in vuls:
            f.write(line+"\n")

def run(res):
    LOG.pprint("+", "start program...",GREEN)
    LOG.pprint("+", "fetching vul list...",GREEN)
    #获取漏洞列表
    sf = FetchVulInSF()
    vuls=[]
    if res.has_key('num'):
        vuls = sf.fetchLine(res['num'], proxy=res['proxy'])
    elif res.has_key('date'):
        vuls=sf.fetch(res['date'], proxy=res['proxy'])
    store(vuls)#储存获取的最新的url
    LOG.pprint("+", "fecthing vul details...",GREEN)
    #获取对应列表的漏洞详情
    fc = FetchContentSF(vuls, proxy=res['proxy'])
    results = fc.fetch()
    results=[temp for temp in results if temp!=None]
    if results==[]:
        LOG.pprint("+", "nothing to transfer...",GREEN)
        LOG.pprint("+", "done",GREEN)
        sys.exit(0)
    # print results
    LOG.pprint("+", "start transfer...",GREEN)
    #开始翻译漏洞
    tv = TransferVuls(results)
    res = tv.dealWithSF()
    # print res
    LOG.pprint("+", "transfer done...",GREEN)
    LOG.pprint("+", "output file to " + VULDB,GREEN)
    #生成文件
    oftt=OutputFileToTxt(res)
    oftt.output()
    LOG.pprint("+", "log CVE db done...",GREEN)
    LOG.pprint("+", "output vul excel...",GREEN)
    test = OutputFileToExcel(results, 'http://securityfocus.com')
    test.output()
    LOG.pprint("+", "done",GREEN)
if __name__=='__main__':
    import sys
    reload(sys)
    sys.setdefaultencoding('utf8')

    parser = argparse.ArgumentParser()
    parser.add_argument('-n',type=int,help="本次需要获取漏洞总数")
    parser.add_argument('--proxy', help="代理ip，支持http代理，如http://127.0.0.1:8087")
    parser.add_argument('--date', help="设置获取漏洞的开始日期，格式为YYYY-MM-DD")
    args=parser.parse_args()
    res={'proxy':False}
    if args.proxy:
        HTTP_PROXY=args.proxy
        res['proxy']=True
    if args.n:
        res['num']=args.n
    if args.date:
        res['date']=args.date
    if args.n or args.date:
        run(res)