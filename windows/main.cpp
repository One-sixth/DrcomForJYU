#include "DrcomForJY.h"
#include <string>
#include <iostream>
#include <vector>
#include <fstream>

#pragma warning(disable:4996)

using namespace std;

int main()
{
	unsigned int a;
	string userName;
	string password;
	vector<string> devNameList;
	vector<string> descriptionList;
	
	DrcomForJY dr;

	ifstream f;
	f.open("autologin.txt");
	if (f.is_open())
	{
		printf("正在进行自动登陆\n");
		f >> userName;
		printf("帐号：%s\n\n", userName.c_str());
		f >> password;
		f.close();
	}
	else
	{
		printf("请输入用户名\n");
		cin >> userName;
		printf("已输入用户名\n");
		printf("请输入密码\n");
		cin >> password;
		printf("已输入密码\n\n");
	}
	dr.SetUserName(userName);
	dr.SetPassword(password);

	printf("列出所有可用网卡\n\n");
	dr.ListDev(devNameList, descriptionList);
	for (size_t i = 0; i < devNameList.size(); i++)
	{
		printf("序号 %d\t%s\n", i, descriptionList[i].c_str());
	}
	putchar('\n');
	
	for (size_t i = 0; i < devNameList.size(); i++)
	{
		if (strstr(descriptionList[i].c_str(), "Realtek"))
		{
			a = i;
			printf("自动选择 Realtek 网卡 %s\n", descriptionList[i].c_str());
			goto mark_end;
		}
	}
	printf("没找到Realtek网卡\n");

mark_reset_net_card:
	printf("请输入你要使用的网卡的序号\n");
	scanf_s("%ud", &a);
	//用来吃掉回车
	getchar();
	if (a >= descriptionList.size())
	{
		printf("不存在该网卡\n");
		goto mark_reset_net_card;
	}

	
mark_end:

	bool b = dr.SelectDev(devNameList[a]);
	if (!b)
	{
		printf("设置选定网卡失败\n请重新设置\n失败原因：%s\n", dr.GetError().c_str());
		goto mark_reset_net_card;
	}
	//设置超时时间
	dr.SetOverTime(1000);
	dr.Login();

	if (dr.GetError() == "")
		printf("\n登陆成功\n");
	else
	{
		printf("\n登录失败:%s\n", dr.GetError().c_str());
	}
	printf("\n按下回车结束程序\n");
	getchar();
	getchar();
	return 0;
}