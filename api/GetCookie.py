#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Created by wh1t3P1g at 2016/11/11


from Config import ROOT,HTTPCONTAINER
import os

code="var cd,dc='__jsl_clearance=1478827124.023|0|';var orders=[(-~![]+[!{}, []][-~![]])+(-~![]+[!{}, []][-~![]]),[-~((-~-~[])*[-~-~[]])],[(-~~~!{}|2)],(-~![]+[!{}, []][-~![]]),[8],(-~![]+[!{}, []][-~![]])+[(-~~~!{}|2)],[(-~-~[])*[-~-~[]]-~~~!{}-~[]-~[]-~[]-~[]],(-~![]+[!{}, []][-~![]])+(~~{}+[]+[]),(-~![]+[!{}, []][-~![]])+[(-~![]<<-~![])],(~~{}+[]+[]),[((+!-[])<<-~[]-~[])],[(-~![]<<-~![])],(-~![]+[!{}, []][-~![]])+[((+!-[])<<-~[]-~[])],[(-~~~!{}|(-~![]<<-~![]))-~((-~~~!{}|(-~![]<<-~![])))],((+!-[])-~((-~-~[])*[-~-~[]])+[]+[[]][~~{}])];cd=Array(orders.length);for(var i=0;i<orders.length;i++){cd[orders[i]]=[({}+[]+[[]][~~{}]).charAt(-~[]),[![]+[[]][(+[])]][0].charAt(-~-~[])+({}+[!{}, []][-~![]]).charAt((2<<2)),[![]+[[]][(+[])]][0].charAt(-~-~[]),[(-~~~!{}|2)],'RwqPPEg',[(-~~~!{}|2)],[(-~-~[])*[-~-~[]]-~~~!{}-~[]-~[]-~[]-~[]]+(~~{}+[]+[])+[(+!-[])/~~[]+[]+[]][0].charAt(~~[])+(~~{}+[]+[]),'kG','%','L','Am','hmx','D',(!+[]+[!{}, []][-~![]]).charAt(~~!{}),'RL'][i]};cd=cd.join('');dc+=cd;"

class GetCookie:
    def __init__(self):
        self.headers = {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Encoding": "gzip, deflate, sdch",
            "Referer": "http://www.cnvd.org.cn/",
            "Upgrade-Insecure-Requests": "1",
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.12; rv:49.0) Gecko/20100101 Firefox/49.0",
            "Accept-Language": "zh-CN,zh;q=0.8"
        }
        self.url="http://www.cnvd.org.cn/"

    def getCookie(self):
        cookie=[]
        #第一次握手，获取js文件
        HTTPCONTAINER.setHeaders(self.headers)
        r=HTTPCONTAINER.get(self.url)
        #根据js生成cookie
        content=r.content.replace('\x00','')[8:-10]
        content=content.replace('eval','')
        cookie.append(r.headers['Set-Cookie'].split(';')[0])
        cookie.append(self.calCookie(content).strip())
        self.headers['Cookie']='; '.join(cookie)
        #第二次握手，获取剩余的cookie
        HTTPCONTAINER.setHeaders(self.headers)
        r=HTTPCONTAINER.get(self.url)
        temp=r.headers['Set-Cookie'].split(',')
        for t in temp:
            if '=' in t.split(';')[0]:
                cookie.append(t.split(';')[0])
        return '; '.join(cookie)

    def calCookie(self,code):
        with open(ROOT+'/tmp/temp.txt','w') as f:
            f.write(code)
        # print code
        tmp= os.popen('java -cp '+ROOT+'/api/ CnvdJSLCookie '+ROOT+'/tmp/temp.txt').readlines()
        return tmp[0]

if __name__=='__main__':
    gc=GetCookie()
    print gc.getCookie()