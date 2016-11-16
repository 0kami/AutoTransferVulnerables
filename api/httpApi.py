#!/usr/bin/env python
# -*- coding: utf-8 -*-
# __author__ = 'gmfork'

import requests,sys

class httpContainer:
    def __init__(self,LOG="",HEADERS="",HTTP_PROXY="",HTTPS_PROXY="",TIMEOUT=5):
        self.LOG=LOG
        self.HEADERS=HEADERS
        self.TIMEOUT=TIMEOUT
        self.proxyDict = {
            "http": HTTP_PROXY,
            "https": HTTPS_PROXY
        }
    def setHttpProxy(self,proxy):
        self.proxyDict['http']=proxy

    def setHttpsProxy(self,proxy):
        self.proxyDict['https'] = proxy

    def setTimeOut(self,timeout):
        self.TIMEOUT=timeout

    def setHeaders(self,headers):
        self.HEADERS=headers

    def get(self,url,proxy=False):
        error_times=0
        while error_times<10:
            r=self.__get(url,proxy)
            try:
                if r or r.status_code==521:
                    return r
                error_times+=1
            except:
                error_times += 1
        self.LOG.pprint("-","http error times more than 10,program exit.",31)
        sys.exit(0)

    def post(self,url,data,proxy=False):
        error_times=0
        while error_times<3:
            r=self.__post(url,data,proxy)
            # print r.status_code
            if r:
                return r
            error_times+=1
        self.LOG.pprint("-", "http error times more than 10,program exit.", 31)
        return "error"
    def __get(self,url,proxy=False):
        try:
            if proxy:
                r = requests.get(url, headers=self.HEADERS, proxies=self.proxyDict, timeout=self.TIMEOUT)
            else:
                r = requests.get(url, headers=self.HEADERS, timeout=self.TIMEOUT)
            return r
        except KeyboardInterrupt:
            self.LOG.pprint('+','stop by user',32)
            sys.exit(0)
        except:
            self.LOG.pprint("-", "http error, get " + url + " again", 31)
            return None

    def __post(self,url,data,proxy=False):
        try:
            if proxy:
                r = requests.post(url,data=data, headers=self.HEADERS, proxies=self.proxyDict, timeout=self.TIMEOUT)
            else:
                r = requests.post(url,data=data, headers=self.HEADERS, timeout=self.TIMEOUT)
            return r
        except KeyboardInterrupt:
            self.LOG.pprint('+','stop by user',32)
            sys.exit(0)
        except:
            self.LOG.pprint("-", "http error, post " + url + " again", 31)
            return None

