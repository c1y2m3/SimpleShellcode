#include "dwBmpSize.h"
#include <iostream>
using namespace std;

CBMPHide::CBMPHide()
{
	sBmpFileName = "";
	pBuf = 0;
	dwBmpSize = 0;
	ptxtBuf = 0;
	pExEBuf = 0;
}

CBMPHide::~CBMPHide()
{

}

bool CBMPHide::setBmpFileName(char* szFileName)
{
	this->sBmpFileName = szFileName;
	if (pBuf)	//如果已经生成就释放掉
	{
		delete[]pBuf;
	}

	HANDLE hfile = CreateFileA(szFileName, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, 0);
	if (hfile == INVALID_HANDLE_VALUE)
	{
		return false;
	}

	//和struct BITMAPFILEHEADER bmfh里面的 bfSize的大小应该是一样的。
	dwBmpSize = GetFileSize(hfile, 0);	//获取文件的大小
	pBuf = new byte[dwBmpSize + 83968];
	DWORD dwRead = 0;
	ReadFile(hfile, pBuf, dwBmpSize, &dwRead, 0);
	if (dwRead != dwBmpSize)
	{
		delete[]pBuf;
		pBuf = 0;
		return false;
	}
	CloseHandle(hfile);
	m_fileHdr = (BITMAPFILEHEADER*)pBuf;
	m_infoHdr = (BITMAPINFOHEADER*)(pBuf + sizeof(BITMAPFILEHEADER));
	return true;	//成功话就是文件的内容读取到pBuf里面
}


int CBMPHide::getBmpWidth()
{
	return m_infoHdr->biWidth;
}

int CBMPHide::getBmpHeight()
{
	return m_infoHdr->biHeight;
}

int CBMPHide::getBmpBitCount()
{
	return m_infoHdr->biBitCount;
}

bool CBMPHide::save()
{
	string sDstFileName = "save.bmp";
	HANDLE hfile = CreateFileA(sDstFileName.c_str(),
		GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL,
		CREATE_ALWAYS, 0, 0);
	if (hfile == INVALID_HANDLE_VALUE)
	{
		return false;
	}

	DWORD dwWritten = 0;
	WriteFile(hfile, pBuf, dwBmpSize + 83968, &dwWritten, 0);
	if (dwBmpSize != dwWritten)
	{
		return false;
	}
	CloseHandle(hfile);
	return true;
}
//隐藏一个字符串到图片中，把字符串拆成字节，写入每个像素的alpha通道中
bool CBMPHide::hideString2BMP(char* szStr2Hide)
{
	LPBYTE pAlpha = pBuf + m_fileHdr->bfOffBits + 3;	//第一个像素的通道位置
	//cout << pAlpha << endl;
	int nHide;	//成功隐藏的字节数

	//每次循环写入一个字节，吸入alpha通道
	//(pAlpha - pBuf) < m_fileHdr->bfSize这个是判断字符串是太大，图片不能隐藏
	for (nHide = 0; (pAlpha - pBuf) < m_fileHdr->bfSize && szStr2Hide[nHide] != 0; nHide++, pAlpha += 4)
	{
		//cout << nHide << endl;
		*pAlpha = szStr2Hide[nHide];	//写入一个字节
		//cout << pAlpha << endl;
	}

	return true;
}

void CBMPHide::showStringInBmp(char* szBmpFIleName/*=NULL*/)
{
	string sDstFileName = "";
	sDstFileName = szBmpFIleName;

	HANDLE hfile = CreateFileA(sDstFileName.c_str(),
		GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL,
		OPEN_EXISTING, 0, 0);
	if (hfile == INVALID_HANDLE_VALUE)
	{
		return;
	}
	DWORD dwSize = GetFileSize(hfile, 0);
	LPBYTE pBuf1 = new byte[dwSize];

	DWORD dwRead = 0;

	ReadFile(hfile, pBuf1, dwSize, &dwRead, 0);
	CloseHandle(hfile);

	//文件内容读取到pBuf1中
	BITMAPFILEHEADER *pHdr = (BITMAPFILEHEADER *)pBuf1;
	LPBYTE pStr = pBuf1 + pHdr->bfOffBits + 3;
	char szTmp[1280];
	RtlZeroMemory(szTmp, 1280);
	for (int i = 0; i < 1280; i++)
	{
		if (*pStr == 0 || *pStr == 0xFF)
		{
			break;
		}
		szTmp[i] = *pStr;
		pStr += 4;
	}
	printf_s(szTmp);

	delete[]pBuf1;
}



