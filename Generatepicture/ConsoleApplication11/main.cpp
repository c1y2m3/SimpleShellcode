// ConsoleApplication11.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>
#include "dwBmpSize.h"
int main(int argc, char* argv[])
{
	if (argc < 2)
	{
		wprintf(L"Command: %S <SHELLCODE> ...\n", argv[0]);
		return -1;
	}


	CBMPHide hide;
	hide.setBmpFileName((char*)"test.bmp");
	printf_s("test.bmp width:%d,height:%d,bitCount%d\n",
		hide.getBmpWidth(),
		hide.getBmpHeight(),
		hide.getBmpBitCount());
	char * shellcode = argv[1];
	hide.hideString2BMP((char*)shellcode);
	hide.save();
	cout << shellcode << endl;
}

