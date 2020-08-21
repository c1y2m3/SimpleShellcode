#define  _CRT_SECURE_NO_WARNINGS
#pragma  once
#include <string>
#include <Windows.h>
using namespace std;

class CBMPHide
{
public:
	CBMPHide();
	~CBMPHide();

	bool setBmpFileName(char* szFileName);	//设置Bmp文件名

	int getBmpWidth();	//获取宽度
	int getBmpHeight();	//获取高度
	int getBmpBitCount();	//获取Bit总数
	bool save();

	bool hideString2BMP(char* szStr2Hide);	//隐藏String到BMP文件中
	void showStringInBmp(char* szBmpFIleName = NULL);	//展示

	void savetxtFile(char* FileName);	//隐藏txt文件到bmp图像中
	void showtxtFile(char* szBmpFIleName = NULL);	//解密出txtFile

	void saveExeFile(char* FileName);
	void showExeFile(char* szBmpFIleName = NULL);

private:
	DWORD dwBmpSize;	//图片文件大小
	DWORD dwTxTSize;
	DWORD dwExESize;

	string sBmpFileName;
	string sTxTFileName;
	string sExEFileName;

	LPBYTE pBuf;	//用于存放图片信息的内存
	LPBYTE ptxtBuf;	//用于存放txt信息的内存
	LPBYTE pExEBuf;	//用于存放exe信息的内存

	BITMAPFILEHEADER* m_fileHdr;
	BITMAPINFOHEADER* m_infoHdr;
};