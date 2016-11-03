#!/usr/bin/env python
# -*- coding: utf-8 -*-
# __author__ = 'gmfork'

import requests,sys

class httpContainer:
    def __init__(self,LOG="",HEADERS="",HTTP_PROXY="",HTTPS_PROXY="",TIMEOUT=5):
        self.LOG=LOG
        self.HEADERS=HEADERS
        self.HTTP_PROXY=HTTP_PROXY
        self.HTTPS_PROXY=HTTPS_PROXY
        self.TIMEOUT=TIMEOUT
    def get(self,url,proxy=False):
        error_times=0
        while True:
            r=self._get(url,proxy)
            if r:
                return r
            else:
                error_times+=1
                if error_times==10:
                    self.LOG.pprint("-","http error times more than 10,program exit.",32)
                    sys.exit(0)
    def _get(self,url,proxy=False):
        try:
            if proxy:
                proxyDict = {
                    "http": self.HTTP_PROXY,
                    "https":self.HTTPS_PROXY
                }
                r = requests.get(url, headers=self.HEADERS, proxies=proxyDict, timeout=self.TIMEOUT)
            else:
                r = requests.get(url, headers=self.HEADERS, timeout=self.TIMEOUT)
            return r
        except:
            self.LOG.pprint("-", "http error, get " + url + " again", 32)
            return None
