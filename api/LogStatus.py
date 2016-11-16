#!/usr/bin/env python
# -*- coding: utf-8 -*-
# __author__ = 'gmfork'

import time

class LogStatus:
    def pprint(self,flag,content,color):
        print "\033[0{color}m[{flag}] [{time}] {content} \033[0m" \
            .format(color=color,flag=flag, time=time.asctime(time.localtime(time.time())), content=content)
