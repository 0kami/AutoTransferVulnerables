#!/usr/bin/python
# -*- coding: utf-8 -*-
# __author__ = 'gmfork'


from app import App,HTTP_PROXY

import argparse


def start():

    parser = argparse.ArgumentParser()
    parser.add_argument('-n', type=int, help="本次需要获取漏洞总数")
    parser.add_argument('--proxy', help="代理ip，支持http代理，如http://127.0.0.1:8087")
    parser.add_argument('--date', help="设置获取漏洞的开始日期，格式为YYYY-MM-DD")
    args = parser.parse_args()
    res = {'proxy': False,'num':'', 'date':''}
    if args.proxy:
        HTTP_PROXY = args.proxy
        res['proxy'] = True
    if args.n:
        res['num'] = args.n
    if args.date:
        res['date'] = args.date
    if args.n or args.date:
        app=App(res)
        app.run()
if __name__=='__main__':
    import sys
    reload(sys)
    sys.setdefaultencoding('utf8')

    start()