#!/usr/bin/env python
# -*- coding: utf-8 -*-
# __author__ = 'gmfork'

from Config import HTTPCONTAINER,LOG
import re
from GetCookie import GetCookie
class Check:
    def __init__(self,proxy=False):

        self.apiurl="http://www.cnvd.org.cn/flaw/list.htm?flag=true"
        self.proxy=proxy
        self.size=5

    def load(self):
        gc = GetCookie()
        self.headers = {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Encoding": "gzip, deflate, sdch",
            "Referer": "http://www.cnvd.org.cn/",
            "Upgrade-Insecure-Requests": "1",
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.12; rv:49.0) Gecko/20100101 Firefox/49.0",
            "Accept-Language": "zh-CN,zh;q=0.8",
            "Cookie": gc.getCookie().strip()
        }
        return self.check('CVE-2016-6662')
    def check(self,cve):
        error_times=0
        data="keyword=&condition=1&keywordFlag=0&cnvdId=&cnvdIdFlag=0&baseinfoBeanbeginTime=&baseinfoBeanendTime=&baseinfoBeanFlag=0&refenceInfo="+cve+"&referenceScope=1&manufacturerId=-1&categoryId=-1&editionId=-1&causeIdStr=&threadIdStr=&serverityIdStr=&positionIdStr="
        while error_times<5:
            HTTPCONTAINER.setHeaders(self.headers)
            # print HTTPCONTAINER.HEADERS
            r=HTTPCONTAINER.post(self.apiurl,data,self.proxy)
            if r=='error':
                LOG.pprint('-','cncert cookie not work',31)
                self.load()
                error_times+=1
            else:
                pattern=re.compile(r'<span>共\&nbsp\;([0-9]*)\&nbsp\;条\s*</span>')
                check=pattern.findall(r.content)[0]
                return int(check)
        return 0
