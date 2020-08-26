### 0x01 前言

将Shellcode隐写到正常BMP图片中，把字符串拆成字节，写入每个像素的alpha通道中，然后上传到可信任的网站下偏移拼接shellcode进行远程动态加载，能有效地增加了免杀性和隐匿性。
参考文章：https://mp.weixin.qq.com/s/QZ5YlRZN47zne7vCzvUpJw

