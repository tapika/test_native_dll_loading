#include <stdio.h>


extern "C" __declspec(dllexport) void HelloDll2()
{
	printf("Hello world 2\r\n");
}

