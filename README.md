# EHole_magic
在安全测试时，安全测试人员信息收集中时可使用它进行指纹识别，

对识别出来的重点资产进行进行漏洞检测，不影响原版功能的使用（如：识别出spring-boot则会对spring—boot的漏洞进行检测）
不影响原版功能的使用

# 运行流程

<img width="676" alt="image" src="https://github.com/lemonlove7/EHole_magic/assets/56328995/97b5c907-ca20-465e-bd04-4043b16d1f7e">


# 使用
默认不开启，在poc.ini中将poc=no改为poc=yes开启

```
ehole finger -s domain="baidu.com"  # 从fofa语法中寻找
ehole finger -l 1.txt  # 从文件中加载url扫描
ehole finger -u http://www.baidu.com # 单个url检测
```
# 使用截图
<img width="930" alt="image" src="https://github.com/lemonlove7/EHole_magic/assets/56328995/e4064f38-6458-4778-a2f5-b7db2de54b1d">



## 参考优秀项目
POC-bomber：https://github.com/tr0uble-mAker/POC-bomber

peiqi文库：https://peiqi.wgpsec.org

EHole：https://github.com/EdgeSecurityTeam/EHole




