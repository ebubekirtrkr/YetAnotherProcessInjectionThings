#include <Windows.h>
#include <TlHelp32.h>
#include <stdio.h>

DWORD getTargetPid( wchar_t* targetName);
int main() {
	DWORD target_pid = getTargetPid((wchar_t*)L"notepad.exe");
	//printf("target_pid :%d\n", target_pid);
	
	HANDLE target_process = OpenProcess(PROCESS_ALL_ACCESS,FALSE,target_pid);

	HMODULE kernel32_h = GetModuleHandle(L"Kernel32.dll");
	LPTHREAD_START_ROUTINE  loadLibraryAddress = (LPTHREAD_START_ROUTINE)GetProcAddress(kernel32_h, "LoadLibraryA");
	LPCSTR  dllpath = "C:\\Users\\User\\Desktop\\DLLInjection_DLL.dll";
	LPVOID dllPathAddress = VirtualAllocEx(target_process, NULL, strlen(dllpath),  MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	WriteProcessMemory(target_process, dllPathAddress, dllpath, strlen(dllpath), NULL);
	CreateRemoteThread(target_process, NULL, 0, loadLibraryAddress, dllPathAddress, 0, NULL);
}

DWORD getTargetPid( wchar_t* targetName) {
	PROCESSENTRY32 p32;
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPALL, 0);
	p32.dwSize = sizeof(PROCESSENTRY32);
	if(Process32First(hSnapshot, &p32)){
		do {
			/*
			wprintf(L"name : %s\t", p32.szExeFile);
			printf("pid :%d\n", p32.th32ProcessID);
			

			*/
			if (! wcscmp(targetName,p32.szExeFile)) {
				return  p32.th32ProcessID;
			}
		} while (Process32Next(hSnapshot, &p32));
	}
}
