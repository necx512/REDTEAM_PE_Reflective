// code mostly stolen from pabloko's comment in https://gist.github.com/xpn/e95a62c6afcf06ede52568fcd8187cc2
#include <iostream>
#include <metahost.h>
#include <corerror.h>
#pragma comment(lib, "mscoree.lib")

int main()
{
    ICLRMetaHost* metaHost = NULL;
    ICLRRuntimeInfo* runtimeInfo = NULL;
    ICLRRuntimeHost* runtimeHost = NULL;
    DWORD pReturnValue;

    CLRCreateInstance(CLSID_CLRMetaHost, IID_ICLRMetaHost, (LPVOID*)&metaHost);
    metaHost->GetRuntime(L"v4.0.30319", IID_ICLRRuntimeInfo, (LPVOID*)&runtimeInfo);
    runtimeInfo->GetInterface(CLSID_CLRRuntimeHost, IID_ICLRRuntimeHost, (LPVOID*)&runtimeHost);
    runtimeHost->Start();
    HRESULT res = runtimeHost->ExecuteInDefaultAppDomain(L"C:\\Users\\seb\\source\\repos\\Rubeus\\Rubeus\\bin\\Release\\Rubeus.exe", L"CLRHello1.Program", L"spotlessMethod", L"test", &pReturnValue);
    if (res == S_OK)
    {
        std::cout << "CLR executed successfully\n";
    }
    else {
        std::cout << "CLR failed\n";
    }

    runtimeInfo->Release();
    metaHost->Release();
    runtimeHost->Release();
    return 0;
}