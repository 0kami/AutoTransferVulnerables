#!/usr/bin/env python
# -*- coding: utf-8 -*-
# __author__ = 'gmfork'

import re,time,random

from FetchVuls import FetchVulInSF
from multiprocessing.pool import ThreadPool
from Config import *

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

        info = self.fetchInfo(url)
        info['url']=url
        if info.has_key('CVE') and info['CVE'] not in CVEDB:
            discuss = self._fetchDiscussion(url)
            exploit = self._fetchExploit(url)
            solution = self._fetchSolution(url)
            references=self._fetchReferences(url)
            LOG.pprint("+","fetch "+url+" details done",GREEN)
            return dict(dict(dict(dict(info, **discuss), **exploit), **solution),**references)
        LOG.pprint("-","已存在CVE漏洞库中 "+url+", 不载入，请人工确认",RED)

    def _fetchInfo(self,url):
        url=url+"/info"
        r = HTTPCONTAINER.get(url, self.proxy)

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

    def _fetchReferences(self,url):
        url+="/references"
        r = HTTPCONTAINER.get(url, self.proxy)

        pattern=re.compile(
            r'<li><a href="([\s\S]+?)">')
        results=pattern.findall(r.content)
        # print results
        res=[result for result in results if '/bid/' not in result]
        # print res
        return {'references':"\n".join(res)}

    def _fetchDiscussion(self,url):
        url=url+"/discuss"
        r = HTTPCONTAINER.get(url, self.proxy)
        pattern = re.compile(
            r'<div id="vulnerability">\s*<span class="title">([\s\S]*?)</span><br/><br/>\s*([\s\S]*?)\s*</div>')
        results = pattern.findall(r.content)[0]
        temp=results[1].replace('<br/>','')
        temp=' '.join(temp.split())
        return {"title":results[0],
                "discuss":temp}

    def _fetchExploit(self,url):
        url=url+"/exploit"
        r = HTTPCONTAINER.get(url, self.proxy)

        pattern = re.compile(
            r'<div id="vulnerability">\s*<span class="title">[\s\S]*?</span><br/><br/>\s*([\s\S]*?)\s*</div>')
        res = pattern.findall(r.content)
        temp = res[0].replace('<br/>', '')
        temp = ' '.join(temp.split())
        return {"exploit":temp}

    def _fetchSolution(self,url):
        url=url+"/solution"
        r = HTTPCONTAINER.get(url, self.proxy)

        pattern = re.compile(
            r'<b>Solution:</b><br/>\s*([\s\S]*?)\s*</div>')
        res = pattern.findall(r.content)
        temp = res[0].replace('<br/>', '')
        temp = ' '.join(temp.split())
        return {"solution":temp}

class FetchContentSB:
    def __init__(self,vuls,proxy):
        self.vuls = vuls
        self.size = 6
        self.proxy = proxy

    def fetch(self):
        try:
            pool=ThreadPool(self.size)
            res=pool.map(self.fetchALL,self.vuls)
            pool.close()
            pool.join()
            return res
        except:
            print '=== STEP ERROR INFO START'
            import traceback
            traceback.print_exc()
            print '=== STEP ERROR INFO END'
            return []

    def fetchALL(self,url):
        pass

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
