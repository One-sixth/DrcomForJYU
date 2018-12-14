# DrcomForJYU

# 此Repo已经过时，做存档处理

# 简介
嘉应学院的学生端有线网络登录器

由项目 https://github.com/drcoms/drcom-generic 修改而来

强迫症不喜欢学校自带的，于是自己弄了一个

弄了 Windows 版 和 Linux 版
算是方便喜欢使用Linux的把

没有考虑心跳包，因为我这里没有心跳包都不会断线
仅仅只有802.1x验证
不过实际测试挺稳定的

第一次登陆可能会失败，多登陆几遍试试

我没有教师端的登录器，也没有教师端的网络，只是用于学生宿舍联网，所以如果用于教室登陆我也不知能否成功

#使用教程
## windows版教程

安装winpcap 4.1.3，已安装的忽略

进入 网络和共享中心 设置你的静态IP，已设置好的忽略

如果你不需要自动登陆，直接打开 Drcom2.exe 按照程序提示操作

如果要自动登陆，在 Drcom2.exe 所在目录下新建一个文件名为 autologin.txt 

示例 autologin.txt

-----autologin.txt------------

你的帐号，不能有多余的字符，空格都不能有

你的密码，不能有多余的字符，空格都不能有

------end---------------------


设置好自动登陆文件后双击就能上网了

如果你的有线网卡不是Realtek的话还需要选择你的有线网卡


## linux版教程

设置好你的有线网卡的IP，并且把config.txt里面的IP改成你的IP

设置好你的路由表

cd 到Drcom2.elf所在目录

例如 192.168.100.10 是你的网关 route add default gw 192.168.100.10

自动登陆文件autologin.txt跟上面是一样的

你需要手动选择网卡



# 如何编译

windows 文件夹是VS2015的项目，用VS2015直接打开 sln文件 直接就能编译了


linux 文件夹是用于linux，从windows版的那里小小修改了一下，以便于 g++ 编译

需要依赖包 g++ libpcap0.8-dev

sudo apt install g++ libpcap0.8-dev

cd “Drcom2/linux”

chmod +x make.sh

sh make.sh

编译完成

# 许可证


不得用于商业用途，本项目内我写的源代码符合 AGPLv3 协议


特别指出禁止任何个人或者公司将 DrcomForJYU 的代码投入商业使用，由此造成的后果和法律责任均与本人无关。

项目内的 WpdPack 文件夹 来自 http://www.winpcap.org/ 的 4.1beta5_WpdPack.zip，它原来是什么协议就是什么协议

项目内的 WinPcap_4_1_3.exe 来自 http://www.winpcap.org/ ，它原来是什么协议就是什么协议

