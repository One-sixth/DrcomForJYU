#pragma once
#include <string>
#include <vector>
using namespace std;

class DrcomForJY
{
public:
	DrcomForJY();
	~DrcomForJY();

public:
	bool ListDev(vector<string> &devNameList, vector<string> &descriptionList);	//�г����п�������
	bool SelectDev(string devName);												//ѡ��һ��������ѡ���ͬʱ�������������ʼ��

	void SetUserName(string userName);
	void SetPassword(string password);
	void Login();
	void Logoff();
	string GetError();

	void SetOverTime(unsigned int ms);

private:
	bool LogoffEapOL();
	bool StartEapOL();
	bool WaitingRequestUserName(char id[1]);
	bool ResponseUserName(char id[1], const char *userName);
	bool WaitingRequestPasswork(char id[1], char challengeMD5[16]);
	bool ResponsePasswork(char id[1], const char *userName, const char *pwd, const char challengeMD5[16]);
	bool WaitingSuccess();

private:
	string userName;
	string password;
	unsigned int overTime = 500;			//��ʱʱ��Ĭ������Ϊ500����
	const unsigned int listenTime = 100;	//�����˿ڳ�ʱ����Ϊ100ms

private:
	//����ʱ����
	char id;
	void *pcapDev = nullptr;
	char clientMac[6];
	char clientIp[4];
	string error;
	int overedTime = 0;					//�Ѿ���ʱ��ʱ��

	vector<string> devList;
	vector<string> devDescriptionList;

	const char NearestMac[6] ={'\x01','\x80','\xc2','\x00','\x00','\x03'};
};

