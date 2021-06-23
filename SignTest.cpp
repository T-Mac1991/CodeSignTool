#include <windows.h>
#include <cryptuiapi.h>
#include <iostream>
#include <string>

#pragma comment(lib, "Cryptui.lib")

const std::wstring ETOKEN_BASE_CRYPT_PROV_NAME = L"eToken Base Cryptographic Provider";


struct CryptProvHandle
{
	HCRYPTPROV Handle = NULL;
	CryptProvHandle(HCRYPTPROV handle = NULL) : Handle(handle) {}
	~CryptProvHandle() { if (Handle) ::CryptReleaseContext(Handle, 0); }
};

HCRYPTPROV token_logon(const std::wstring& containerName, const std::string& tokenPin)
{
	CryptProvHandle cryptProv;
	if (!::CryptAcquireContext(&cryptProv.Handle, containerName.c_str(), ETOKEN_BASE_CRYPT_PROV_NAME.c_str(), PROV_RSA_FULL, CRYPT_SILENT))
	{
		std::cerr << "CryptAcquireContext failed, error " << std::hex << std::showbase << ::GetLastError() << "\n";
		return NULL;
	}

	if (!::CryptSetProvParam(cryptProv.Handle, PP_SIGNATURE_PIN, reinterpret_cast<const BYTE*>(tokenPin.c_str()), 0))
	{
		std::cerr << "CryptSetProvParam failed, error " << std::hex << std::showbase << ::GetLastError() << "\n";
		return NULL;
	}

	auto result = cryptProv.Handle;
	cryptProv.Handle = NULL;
	return result;
}

int main()
{
	const std::wstring certFile = L"E:/test2.cer";
	const std::wstring containerName = L"AC5099FEE17FBE63"; 
	const std::string tokenPin = "Aa123123";
	const std::wstring timestampUrl = L"http://timestamp.digicert.com"; 
	const std::wstring fileToSign = L"E:/test.exe";

	CryptProvHandle cryptProv = token_logon(containerName, tokenPin);
	if (!cryptProv.Handle)
	{
		return 1;
	}

	CRYPTUI_WIZ_DIGITAL_SIGN_EXTENDED_INFO extInfo = {};
	extInfo.dwSize = sizeof(extInfo);
	extInfo.pszHashAlg = szOID_NIST_sha256; // Use SHA256 instead of default SHA1

	CRYPT_KEY_PROV_INFO keyProvInfo = {};
	keyProvInfo.pwszContainerName = const_cast<wchar_t*>(containerName.c_str());
	keyProvInfo.pwszProvName = const_cast<wchar_t*>(ETOKEN_BASE_CRYPT_PROV_NAME.c_str());
	keyProvInfo.dwProvType = PROV_RSA_FULL;

	CRYPTUI_WIZ_DIGITAL_SIGN_CERT_PVK_INFO pvkInfo = {};
	pvkInfo.dwSize = sizeof(pvkInfo);
	pvkInfo.pwszSigningCertFileName = const_cast<wchar_t*>(certFile.c_str());
	pvkInfo.dwPvkChoice = CRYPTUI_WIZ_DIGITAL_SIGN_PVK_PROV;
	pvkInfo.pPvkProvInfo = &keyProvInfo;

	CRYPTUI_WIZ_DIGITAL_SIGN_INFO signInfo = {};
	signInfo.dwSize = sizeof(signInfo);
	signInfo.dwSubjectChoice = CRYPTUI_WIZ_DIGITAL_SIGN_SUBJECT_FILE;
	signInfo.pwszFileName = fileToSign.c_str();
	signInfo.dwSigningCertChoice = CRYPTUI_WIZ_DIGITAL_SIGN_PVK;
	signInfo.pSigningCertPvkInfo = &pvkInfo;
	signInfo.pwszTimestampURL = timestampUrl.c_str();
	signInfo.pSignExtInfo = &extInfo;

	if (!::CryptUIWizDigitalSign(CRYPTUI_WIZ_NO_UI, NULL, NULL, &signInfo, NULL))
	{
		std::wcerr << L"CryptUIWizDigitalSign failed, error " << std::hex << std::showbase << ::GetLastError() << L"\n";
		return 1;
	}

	std::wcout << L"Successfully signed " << fileToSign << L"\n";
	return 0;
}