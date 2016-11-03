#!/usr/bin/env python
# -*- coding: utf-8 -*-
# __author__ = 'gmfork'

import requests,re,time
from Config import HTTP_PROXY,HEADERS,TIMEOUT,ROOT


class FetchVulInSF:
    '''
    查询securityfocus漏洞列表，url:http://www.securityfocus.com/
    '''
    def __init__(self):
        self.apiurl="http://www.securityfocus.com/cgi-bin/index.cgi?" \
                    "o={start}&l={lines}&c=12&op=display_list&" \
                    "vendor={vendor}&version={version}&title={title}&CVE={CVE}"
        self.oldurl=[]
        self.flag=False
        with open(ROOT+"/url.db","a+") as f:
            while 1:
                buf=f.readline().strip()
                # print buf
                if not buf:
                    break
                self.oldurl.append(buf)
        # print self.oldurl

    def query(self,start,lines=100,date="",vendor="",version="",title="",CVE="",proxy=False):
        '''
        Parameters
        ----------
        start   起始位置
        lines   共查询多少条漏洞 最多100条  默认 100
        date    查询开始时间  范例2016-10-26 默认当前时间
        vendor  厂商  默认为空
        version 版本  默认为空
        title   漏洞标题  默认为空
        CVE     CVE号  默认为空

        Returns 漏洞url列表[title,date,url]
        -------
        '''
        if date=="":
            date=time.strftime("%Y-%m-%d")
        elif date=="null":
            date=""
        url=self.apiurl.format(start=start,lines=lines,vendor=vendor,
                               version=version,title=title,CVE=CVE)
        vuls=[]

        try:
            if proxy:
                proxyDict = {
                    "http": HTTP_PROXY,
                }
                r=requests.get(url,headers=HEADERS,proxies=proxyDict,timeout=TIMEOUT)
            else:
                r = requests.get(url,headers=HEADERS,timeout=TIMEOUT)
            pattern = re.compile(
                r'<a href="/bid/[0-9]+"><span class="headline">([\s\S]+?)</span></a><br/>\s*<span class="date">([0-9]{4}-[0-9]{2}-[0-9]{2})</span><br/>\s*<a href="/bid/[0-9]+">([\s\S]+?)</a><br/><br/>')
            results = pattern.findall(r.content)
            for result in results:
                # print result
                if result[2] in self.oldurl:
                    continue
                if date!="":
                    if time.strptime(result[1],"%Y-%m-%d") >= time.strptime(date,"%Y-%m-%d"):
                        vuls.append(result[2])
                    else:
                        self.flag=True
                else:
                    vuls.append(result[2])

            return vuls
        except:
            print "获取securityfocus漏洞列表出错"
            print '=== STEP ERROR INFO START'
            import traceback
            traceback.print_exc()
            print '=== STEP ERROR INFO END'
            return []
    def fetch(self,date,proxy=False):
        '''
        Parameters
        ----------
        date  2016-10-29

        Returns vuls list
        -------
        '''
        res = []
        t = 0
        num=0
        while 1:
            temp = self.query(t,date=date,proxy=proxy)
            num+=len(temp)
            print "[+] ["+time.asctime(time.localtime(time.time()))+"] " \
                    "Total fecth "+str(num)
            if self.flag:
                res.extend(temp)
                break
            res += temp
            t += 100
        return res
    def fetchLine(self,lines,proxy=False):
        start=0
        res=[]
        while 1:
            temp=self.query(start,lines=100,date="null",proxy=proxy)
            num=len(temp)
            if num > lines:
                res.extend(temp[:lines])
                print "[+] [" + time.asctime(time.localtime(time.time())) + "] " \
                            "Total fecth " + str(lines)
                return res
            elif num==lines:#获取了足够的url
                res.extend(temp)
                print "[+] [" + time.asctime(time.localtime(time.time())) + "] " \
                            "Total fecth " + str(lines)
                return res
            else:
                start+=100
                lines-=num
                res.extend(temp)

class FetchVulInSB:#
    '''
    获取www.auscert.org.au上的漏洞列表
    https://www.auscert.org.au/render.html?it=1&offset=0
    该网站每页固定数量35
    '''
    def __init__(self):
        self.apiurl="https://www.auscert.org.au/render.html?it=1&offset={offset}"
        self.oldurl = []
        self.flag = False
        with open(ROOT + "/url.db", "a+") as f:
            while 1:
                buf = f.readline().strip()
                if not buf:
                    break
                self.oldurl.append(buf)
    def query(self,offset=35,date="",proxy=False):
        if date == "":
            date = time.strftime("%Y-%m-%d")
        elif date == "null":
            date = ""
        vuls=[]
        url=self.apiurl.format(offset=offset)
        try:
            if proxy:
                proxyDict = {
                    "http": HTTP_PROXY,
                }
                r = requests.get(url, headers=HEADERS, proxies=proxyDict, timeout=TIMEOUT)
            else:
                r = requests.get(url, headers=HEADERS, timeout=TIMEOUT)
            pattern = re.compile(
                r'<a href="(render.html?it=[0-9]{0,6})" class="genlink"><b>[\s\S]+?<span class="nodetext">\(([\s\S]+?)\)</span>')
            results = pattern.findall(r.content)
            for result in results:
                # print result
                if result[0] in self.oldurl:
                    continue
                if date != "":
                    if time.strptime(result[1], "%d/%m/%Y") >= time.strptime(date, "%Y-%m-%d"):
                        vuls.append(result[0])
                    else:
                        self.flag = True
                else:
                    vuls.append(result[0])

            return vuls
        except:
            print "获取securityfocus漏洞列表出错"
            print '=== STEP ERROR INFO START'
            import traceback
            traceback.print_exc()
            print '=== STEP ERROR INFO END'
            return []

    def fetch(self, date, proxy=False):
        '''
        Parameters
        ----------
        date  2016-10-29

        Returns vuls list
        -------
        '''
        res = []
        t = 0
        num = 0
        while 1:
            temp = self.query(t, date=date, proxy=proxy)
            num += len(temp)
            print "[+] [" + time.asctime(time.localtime(time.time())) + "] " \
                        "Total fecth " + str(num)
            if self.flag:
                res.extend(temp)
                break
            res += temp
            t += 35
        return res

    def fetchLine(self, lines, proxy=False):
        start = 0
        res = []
        while 1:
            temp = self.query( offset=35, date="null", proxy=proxy)
            num = len(temp)
            if num > lines:
                res.extend(temp[:lines])
                print "[+] [" + time.asctime(time.localtime(time.time())) + "] " \
                        "Total fecth " + str(lines)
                return res
            elif num == lines:  # 获取了足够的url
                res.extend(temp)
                print "[+] [" + time.asctime(time.localtime(time.time())) + "] " \
                        "Total fecth " + str(lines)
                return res
            else:
                start += 100
                lines -= num
                res.extend(temp)

if __name__=='__main__':
    # sf=FetchVulInSF()
    # temp=sf.fetch("2016-10-29")
    # temp=sf.fetchLine(10)
    # print temp
    # print len(temp)
    sb=FetchVulInSB()
    temp=sb.fetch("2016-11-03")
    print temp
    print len(temp)