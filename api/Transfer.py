#!/usr/bin/env python
# -*- coding: utf-8 -*-
# __author__ = 'gmfork'

import requests,json,random,re
from Config import *
from multiprocessing.pool import ThreadPool


class TransferByYouDao:

    ERROR={-1:u"程序出错",
           0:u"正常",
           20:u"要翻译的文本过长",
           30:u"无法进行有效的翻译",
           40:u"不支持的语言类型",
           50:u"无效的key",
           60:u"无词典结果，仅在获取词典结果生效"}
    def __init__(self):
        '''
        Parameters
        ----------
        key  有道api key
        keyfrom 有道api keyfrom
        '''
        self.apiurl=None

    def getRandomKEY(self):
        index=int(random.random() * 10)
        self.apiurl = "http://fanyi.youdao.com/openapi.do?" \
                      "keyfrom=" + str(KEYFROM[index]) + "&key=" + str(KEY[index]) + "&type=data&doctype=json&version=1.1&q={query}"

    def transfer(self,query):
        '''

        Parameters
        ----------
        query  查询的语句

        Returns  {errorcode,errorinfo,translation,query}
        -------

        '''
        self.getRandomKEY()
        url = self.apiurl.format(query=query)
        try:
            r = HTTPCONTAINER.get(url)
            if 'openapi' in r.content:
                return self.transfer(query)
            else:
                data = json.loads(r.content)
                if data['errorCode']==0:
                    return {"errorcode":data['errorCode'],
                            "translation":data['translation'][0],
                            "query":data['query']}
                else:
                    return {"errorcode": data['errorCode'],
                            "translation": "ERROR:<"+self.ERROR[data['errorCode']]+">QUERY:<"+query+">",
                            "query": query}
        except:
            # print "有道api连接不上"
            print '=== STEP ERROR INFO START'
            import traceback
            traceback.print_exc()
            print '=== STEP ERROR INFO END'
            return {"errorcode":-1,
                    "translation":"ERROR<系统错误，可能api被禁用>",
                    "query":query}

    def apitest(self,query):
        url=self.apiurl.format(query=query)
        r=HTTPCONTAINER.get(url)
        data=json.loads(r.content)
        errorCode=data['errorCode']
        if errorCode==0:
            print data['translation'][0]
        else:
            print self.ERROR[errorCode]

class TransferVuls:
    def __init__(self,vuls):
        self.vuls=[vul for vul in vuls if vul]
        self.trans=TransferByYouDao()
    def dealWithSF(self):
        try:
            if self.vuls!=[]:
                pool=ThreadPool(5)
                res=pool.map(self.transfer,self.vuls)
                pool.close()
                pool.join()
                return res
        except:
            print '=== STEP ERROR INFO START'
            import traceback
            traceback.print_exc()
            print '=== STEP ERROR INFO END'

    def transfer(self,line):
        line['ch_title']=self.trans.transfer(line['title'])['translation']
        line['ch_Class']=self.trans.transfer(line['Class'])['translation']
        line['ch_discuss']=self.doTrans(line['discuss'])
        line['ch_exploit']=self.doTrans(line['exploit'])
        line['ch_solution']=self.doTrans(line['solution'])
        # print line
        return line

    def doTrans(self, content):  # 断句并翻译
        pattern = re.compile("([A-Z][\s\S]+?\.)\s+")
        lines = pattern.findall(content)
        res = ""
        for line in lines:
            if len(line) > 200:  # 有道api不能大于200字节
                if '(' in line and ')' in line:
                    temp = re.sub('\([\s\S]+?\)', '()', line)  # 去掉括号后的内容
                    pattern2 = re.compile("\(([\s\S]+?)\)")
                    inline = pattern2.findall(line)[0]  # 取出括号内的内容

                    t = self.trans.transfer(temp)['translation']
                    pos = t.index('(') + 1
                    res += t[:pos] + self.trans.transfer(inline)['translation'] + t[pos:]
            else:
                res += self.trans.transfer(line)['translation']
        return res

if __name__=='__main__':
    # 有道api
    key = 1721019430
    keyfrom = "TransferForLearn"
    query="this is a test"
    youdao=TransferByYouDao(key,keyfrom)
    youdao.apitest(query)
    print youdao.transfer(query)

