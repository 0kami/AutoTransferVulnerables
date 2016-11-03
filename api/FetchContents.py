#!/usr/bin/env python
# -*- coding: utf-8 -*-
# __author__ = 'gmfork'

import requests,re,time,random

from FetchVuls import FetchVulInSF
from multiprocessing.pool import ThreadPool
from Config import HTTP_PROXY,CVEDB,TIMEOUT

class FetchContentSF:
    '''
    获取漏洞内容 包括 漏洞名称 CVE号  类型 最早公开时间  受影响的软件或系统 漏洞起因 安全建议  原始信息来源
    '''
    def __init__(self,vuls,proxy=False):
        self.vuls=vuls
        self.size=6
        self.proxy=proxy
    def setThreadSize(self,size):
        self.size=size

    def fetch(self):
        pool=ThreadPool(self.size)
        res=pool.map(self.fetchALL,self.vuls)
        pool.close()
        pool.join()
        return res

    def fetchALL(self,url):
        # print vuls

        info = self.fetchInfo(url)
        info['url']=url
        if info.has_key('CVE') and info['CVE'] not in CVEDB:
            discuss = self.fetchDiscussion(url)
            exploit = self.fetchExploit(url)
            solution = self.fetchSolution(url)
            references=self.fetchReferences(url)
            print "[+] ["+time.asctime(time.localtime(time.time()))+\
                  "] fetch "+url+" details done"
            return dict(dict(dict(dict(info, **discuss), **exploit), **solution),**references)
        print "[-] ["+time.asctime(time.localtime(time.time()))+\
              "] 已存在CVE漏洞库中 "+url+", 不载入，请人工确认"
    def fetchInfo(self,url):
        url=url+"/info"
        while 1:
            r=self.get(url)
            if r!=None:
                break
            print "[-] ["+time.asctime(time.localtime(time.time()))+\
                  "] http error, get " + url + " again"
        pattern=re.compile(r'\s*<td>\s*<span class="label">([\s\S]+?):</span>\s*</td>\s*<td>\s*([\s\S]*?)\s*</td>')
        results=pattern.findall(r.content)
        res={}
        for line in results:
            if line[0]=='CVE':
                if line[1]=="":
                    res['CVE']="N-A-"+str(int(random.random()*1000))
                else:
                    res['CVE']=line[1][:13]
            elif line[0]=='Vulnerable':
                res['Vulnerable']='\t'.join(line[1].split('\t'))
                res['Vulnerable'] = '\n'.join(res['Vulnerable'].split('\n'))
                res['Vulnerable']=(' '.join(res['Vulnerable'].split())).replace('<br/>','\n')
                # print res['Vulnerable']
            else:
                res[line[0]]=re.sub('<[^<]+?>', '', line[1])
        return res

    def fetchReferences(self,url):
        url+="/references"
        while 1:
            r = self.get(url)
            if r != None:
                break
            print "[-] [" + time.asctime(time.localtime(time.time())) + \
                  "] http error, get " + url + " again"
        pattern=re.compile(
            r'<li><a href="([\s\S]+?)">')
        results=pattern.findall(r.content)
        # print results
        res=[result for result in results if '/bid/' not in result]
        # print res
        return {'references':"\n".join(res)}

    def fetchDiscussion(self,url):
        url=url+"/discuss"
        while 1:
            r = self.get(url)
            if r != None:
                break
            print "[-] ["+time.asctime(time.localtime(time.time()))+\
                  "] http error, get " + url + " again"
        pattern = re.compile(
            r'<div id="vulnerability">\s*<span class="title">([\s\S]*?)</span><br/><br/>\s*([\s\S]*?)\s*</div>')
        results = pattern.findall(r.content)[0]
        temp=results[1].replace('<br/>','')
        temp=' '.join(temp.split())
        return {"title":results[0],
                "discuss":temp}

    def fetchExploit(self,url):
        url=url+"/exploit"
        while 1:
            r = self.get(url)
            if r != None:
                break
            print "[-] [" + time.asctime(time.localtime(time.time())) + \
                  "] http error, get " + url + " again"

        pattern = re.compile(
            r'<div id="vulnerability">\s*<span class="title">[\s\S]*?</span><br/><br/>\s*([\s\S]*?)\s*</div>')
        res = pattern.findall(r.content)
        temp = res[0].replace('<br/>', '')
        temp = ' '.join(temp.split())
        return {"exploit":temp}


    def fetchSolution(self,url):
        url=url+"/solution"
        while 1:
            r = self.get(url)
            if r != None:
                break
            print "[-] [" + time.asctime(time.localtime(time.time())) + \
                  "] http error, get " + url + " again"

        pattern = re.compile(
            r'<b>Solution:</b><br/>\s*([\s\S]*?)\s*</div>')
        res = pattern.findall(r.content)
        temp = res[0].replace('<br/>', '')
        temp = ' '.join(temp.split())
        return {"solution":temp}


    def get(self,url):
        try:
            if self.proxy:
                proxyDict = {
                    "http": HTTP_PROXY,
                    "https": HTTP_PROXY
                }
                r = requests.get(url, proxies=proxyDict,timeout=TIMEOUT)
            else:
                r = requests.get(url,timeout=TIMEOUT)
            return r
        except:
            return None

if __name__=='__main__':

    vuls=FetchVulInSF().fetch("2016-10-29")
    fc=FetchContentSF(vuls)
    print "start:" + time.asctime(time.localtime(time.time()))
    temp= fc.fetch()
    print len(temp)
    print "end:" + time.asctime( time.localtime(time.time()) )
    # fc.fetchInfo("http://www.securityfocus.com/bid/93938")
    # print fc.fetchDiscussion("http://www.securityfocus.com/bid/93938")
    # print fc.fetchExploit("http://www.securityfocus.com/bid/93938")
    # print fc.fecthSolution("http://www.securityfocus.com/bid/93938")
