#!/usr/bin/env python
# -*- coding: utf-8 -*-
# __author__ = 'gmfork'

import re,time,random,sys

from FetchVuls import FetchVulInSF
from Check import Check
from multiprocessing.pool import ThreadPool
from Config import *
from threading import Lock

class FetchContentSF:
    '''
    获取漏洞内容 包括 漏洞名称 CVE号  类型 最早公开时间  受影响的软件或系统 漏洞起因 安全建议  原始信息来源
    '''
    def __init__(self,vuls,proxy=False):
        self.vuls=vuls
        self.size=6
        self.proxy=proxy
        self.check=False
        self.check=Check()
        self.load()
        self.lock=Lock()
        self.pool=ThreadPool(self.size)

    def load(self):
        error_times=0
        LOG.pprint('+', 'load cncert cookie', GREEN)
        while error_times<3:
            code=self.check.load()
            if code:
                break
            LOG.pprint('-', 'load cncert cookie failed, load again', RED)
        LOG.pprint('+', 'load cncert cookie success', GREEN)

    def setThreadSize(self,size):
        self.size=size

    def setCookie(self,cookie):
        self.cookie=cookie
        self.check=True

    def fetch(self):

        res=self.pool.map(self.fetchALL,self.vuls)
        self.pool.close()
        self.pool.join()

        return res

    def fetchALL(self,url):

        info = self._fetchInfo(url)
        info['url']=url
        flag=info.has_key('CVE') and 'N-A' not in info['CVE']
        code=-1000
        if flag:
            if self.lock.acquire(1):
                code=self.check.check(info['CVE'])
                self.lock.release()
            if code==-1:
                LOG.pprint('-','无法获取CNCERT cookie，请查看是否可以正常访问网站',RED)
                self.pool.terminate()
                sys.exit(0)
        try:
            if flag and info['CVE'] in CVEDB:
                LOG.pprint("-", "已存在CVE漏洞库中 " + url + ", 不载入，请人工确认", RED)
            elif flag and code>0:
                LOG.pprint("-", "已存在CNCERT漏洞库中 " + url + ", 不载入", RED)
            elif flag and code==0:
                discuss = self._fetchDiscussion(url)
                exploit = self._fetchExploit(url)
                solution = self._fetchSolution(url)
                company=self._fetchReferences(url)
                references={'references':url}
                LOG.pprint("+","fetch "+url+" details done",GREEN)
                return dict(dict(dict(dict(dict(info, **discuss), **exploit), **solution),**references),**company)
            else:
                LOG.pprint("-", "不存在CVE " + url + ", 不载入，请人工确认", RED)
        except KeyboardInterrupt:
            LOG.pprint('+','user stop',GREEN)
            self.pool.terminate()
            sys.exit(0)

    def _fetchInfo(self,url):
        url=url+"/info"
        HTTPCONTAINER.setHeaders(HEADERS)
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
                res['Vulnerable']=re.sub('<[^<]+?>', '', res['Vulnerable'])
                pattern = re.compile(
                    r'\s*([\S\s]+?)\s[0-9]{1}[\s\S]*?\n')
                product=list(set(pattern.findall(res['Vulnerable'])))
                res['product']="##".join(product).replace('+','').strip()
                # print res['Vulnerable']
            else:
                res[line[0]]=re.sub('<[^<]+?>', '', line[1])
        return res

    def _fetchReferences(self,url):
        '''
        获取解决方案中的url
        获取厂商名
        :param url:
        :return:
        '''
        url+="/references"
        HTTPCONTAINER.setHeaders(HEADERS)
        r = HTTPCONTAINER.get(url, self.proxy)
        content=r.content[r.content.index('<li class="here"><a href='):]
        #正则匹配
        pattern=re.compile(
            r'<li><a href="([\s\S]+?)">([\s\S]+?)</a>\s*\([\s\S]+?\)\s*<br/></li>')
        results=pattern.findall(content)
        data={"company":"","solutionUrl":"","companyUrl":""}
        max=0
        for result in results:
            if "Homepage" in result[1] or "Home Page" in result[1]:
                data['company']=result[1].strip("Homepage").strip("Home Page").strip()
                data['companyUrl']=result[0]
            else:
                if max < len(result[1].strip()):
                    data['solutionUrl']=result[0]
                    max=len(result[1].strip())

        return data

    def _fetchDiscussion(self,url):
        url=url+"/discuss"
        HTTPCONTAINER.setHeaders(HEADERS)
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
        HTTPCONTAINER.setHeaders(HEADERS)
        r = HTTPCONTAINER.get(url, self.proxy)
        pattern = re.compile(
            r'<div id="vulnerability">\s*<span class="title">[\s\S]*?</span><br/><br/>\s*([\s\S]*?)\s*</div>')
        res = pattern.findall(r.content)
        temp = res[0].replace('<br/>', '')
        temp = ' '.join(temp.split())
        return {"exploit":temp}

    def _fetchSolution(self,url):
        url=url+"/solution"
        HTTPCONTAINER.setHeaders(HEADERS)
        r = HTTPCONTAINER.get(url, self.proxy)

        pattern = re.compile(
            r'<b>Solution:</b><br/>\s*([\s\S]*?)\s*</div>')
        res = pattern.findall(r.content)
        temp = res[0].replace('<br/>', '')
        temp = ' '.join(temp.split())
        if "":
            pass
        return {"solution":temp}

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
