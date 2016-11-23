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
		printf("���ڽ����Զ���½\n");
		f >> userName;
		printf("�ʺţ�%s\n\n", userName.c_str());
		f >> password;
		f.close();
	}
	else
	{
		printf("�������û���\n");
		cin >> userName;
		printf("�������û���\n");
		printf("����������\n");
		cin >> password;
		printf("����������\n\n");
	}
	dr.SetUserName(userName);
	dr.SetPassword(password);

	printf("�г����п�������\n\n");
	dr.ListDev(devNameList, descriptionList);
	for (size_t i = 0; i < devNameList.size(); i++)
	{
		printf("��� %d\t%s\n", i, descriptionList[i].c_str());
	}
	putchar('\n');
	
	for (size_t i = 0; i < devNameList.size(); i++)
	{
		if (strstr(descriptionList[i].c_str(), "Realtek"))
		{
			a = i;
			printf("�Զ�ѡ�� Realtek ���� %s\n", descriptionList[i].c_str());
			goto mark_end;
		}
	}
	printf("û�ҵ�Realtek����\n");

mark_reset_net_card:
	printf("��������Ҫʹ�õ����������\n");
	scanf_s("%ud", &a);
	//�����Ե��س�
	getchar();
	if (a >= descriptionList.size())
	{
		printf("�����ڸ�����\n");
		goto mark_reset_net_card;
	}

	
mark_end:

	bool b = dr.SelectDev(devNameList[a]);
	if (!b)
	{
		printf("����ѡ������ʧ��\n����������\nʧ��ԭ��%s\n", dr.GetError().c_str());
		goto mark_reset_net_card;
	}
	//���ó�ʱʱ��
	dr.SetOverTime(1000);
	dr.Login();

	if (dr.GetError() == "")
		printf("\n��½�ɹ�\n");
	else
	{
		printf("\n��¼ʧ��:%s\n", dr.GetError().c_str());
	}
	printf("\n���»س���������\n");
	getchar();
	getchar();
	return 0;
}