# AutoTransferVulnerables
通过有道API翻译[securityfocus](http://www.securityfocus.com/)官网的最新漏洞，实现自动化翻译。
# usage
复制一份Config.py.example到Config.py<br/>
在有道翻译API上申请10个api账号（经测试10个比较稳定）,写入Config.py<br/>
-h查看使用方法<br/>
python main.py -h
# example
python main.py -n number <br/>
python main.py --date YYYY-MM-DD<br/>
支持http代理<br/>
python main.py -n number --proxy=http://127.0.0.1:8087<br/>
默认代理http://127.0.0.1:8087，可在example中修改<br/>
