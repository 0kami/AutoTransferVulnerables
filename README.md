# AutoTransferVulnerables
通过有道API翻译securityfocus官网的漏洞，实现自动化翻译。
# usage
复制一份Config.py.example到Config.py
在有道翻译API上申请10个api账号（经测试10个比较稳定）
-h查看使用方法
python main.py -h
# example
python main.py -n number 
python main.py --date YYYY-MM-DD
支持http代理
python main.py -n number --proxy=http://127.0.0.1:8087
默认代理http://127.0.0.1:8087，可在example中修改
