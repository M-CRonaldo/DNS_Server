# 实验六 解析DNS

## 实验目的

要求学生掌握Socket编程技术，以及DNS协议

## 实验内容

- 要求学生掌握利用Socket进行编程的技术
- 建立一个简单的DNS服务器，接收客户端的请求，查询本地地址表（保存在文件中），查不到，则向现有的DNS服务器（自己输入）发起请求
- 不能采用现有的工具，必须自己一步一步，根据协议进行操作
- 可以让用户选择查询模式（迭代、递归）
- 针对迭代方式，要求每一次步骤，必须点击下一步才能继续，每次都假设查不到，直至最后一个服务器
- 了解DNS报文的格式和步骤
- 必须采用图形界面，查看收到回应的结果
- 把查询的结果，保存在当地文件中，以备后续查询
- 需要记录缓存，并在窗口中展示

## 实验步骤

编程语言：python 3.6

用到的外部库：
- flask
- dnslib

DNS server功能由dnslib实现，Web界面由flask实现

`app.py`共三个线程，主线程是Web界面，子线程一个是UDP的DNS server，一个是TCP的DNS server

端口对应如下：
- 5000/TCP: Flask app
- 5053/UDP
- 5053/TCP

Docker部署：
```bash
docker build -t dns-server . && docker run -p 5053:5053 -p 5053:5053/udp -p 5000:5000 --name dns-server -d  -t  -i  dns-server 
```
