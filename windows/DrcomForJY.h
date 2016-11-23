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
	bool ListDev(vector<string> &devNameList, vector<string> &descriptionList);	//列出所有可用网卡
	bool SelectDev(string devName);												//选择一张网卡，选择的同时将会完成网卡初始化

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
	unsigned int overTime = 500;			//超时时间默认设置为500毫秒
	const unsigned int listenTime = 100;	//监听端口超时设置为100ms

private:
	//运行时所需
	char id;
	void *pcapDev = nullptr;
	char clientMac[6];
	char clientIp[4];
	string error;
	int overedTime = 0;					//已经超时的时间

	vector<string> devList;
	vector<string> devDescriptionList;

	const char NearestMac[6] ={'\x01','\x80','\xc2','\x00','\x00','\x03'};
};

