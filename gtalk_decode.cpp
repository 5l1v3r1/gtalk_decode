/**
 *  The MIT License:
 *
 *  Copyright (c) 2012 Kevin Devine
 *
 *  Permission is hereby granted,  free of charge,  to any person obtaining a 
 *  copy of this software and associated documentation files (the "Software"),
 *  to deal in the Software without restriction,  including without limitation 
 *  the rights to use,  copy,  modify,  merge,  publish,  distribute,  
 *  sublicense,  and/or sell copies of the Software,  and to permit persons to 
 *  whom the Software is furnished to do so,  subject to the following 
 *  conditions:
 *
 *  The above copyright notice and this permission notice shall be included in
 *  all copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS",  WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 *  IMPLIED,  INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 *  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 *  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,  DAMAGES OR OTHER
 *  LIABILITY,  WHETHER IN AN ACTION OF CONTRACT,  TORT OR OTHERWISE,  
 *  ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR 
 *  OTHER DEALINGS IN THE SOFTWARE.
 */
 
#define UNICODE
#define _WIN32_IE 0x0500

#include <cstdio>
#include <string>

#include <windows.h>
#include <wincrypt.h>
#include <Shlwapi.h>
#include <Shlobj.h>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "crypt32.lib")

long gtalk_entropy[4];
long static_key[4] = { 0x69F31EA3, 0x1FD96207, 0x7D35E91E, 0x487DD24F };

/**
 *
 *  Retrieve the current domain\username from thread or process token
 *
 *  returns TRUE for success else FALSE
 *
 */
BOOL GetUserInfo(std::wstring &domain, std::wstring &username) {
    HANDLE hToken;
    DWORD dwTokenSize = 0, dwUserName = 64, dwDomain = 64;
    WCHAR UserName[64], Domain[64];
    SID_NAME_USE peUse;
    PSID pSid = NULL;
    BOOL bResult = FALSE;
    
    OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &hToken);
    
    if (GetLastError() == ERROR_NO_TOKEN) {
      if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        return FALSE;
      }
    }
    
    if (!GetTokenInformation(hToken, TokenUser, 0, 0, &dwTokenSize)) {
      if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
        pSid = new BYTE[dwTokenSize];
        if (pSid != NULL) {
          if (GetTokenInformation(hToken, TokenUser, pSid, 
              dwTokenSize, &dwTokenSize)) {
            bResult = LookupAccountSid(NULL, 
                reinterpret_cast<PTOKEN_USER>(pSid)->User.Sid, 
                UserName, &dwUserName, Domain, &dwDomain, &peUse);
            if (bResult) {
              domain = Domain;
              username = UserName;
            }
          }
          delete []pSid;
        }
      }
    }
    return bResult;
}

/**
 *
 *  Initialize entropy used to encrypt/decrypt passwords
 *  Returns TRUE for success else FALSE
 *
 */
BOOL init_entropy(void) {
    std::wstring domain, username;
    
    BOOL bResult = GetUserInfo(domain, username);
    
    if (bResult) {
      memcpy(gtalk_entropy, static_key, sizeof(static_key));
    
      long M = 2147483647;
      long A = 48271;
      long Q = M / A;
      long R = M % A;
      long seed = 387822687;
      
      seed = A * (seed % Q) - R * (seed / Q);
      seed += M;
      
      long idx = 0;
      
      // mix with username
      for (std::wstring::size_type i = 0;i < username.length();i++) {
        gtalk_entropy[idx++ % 4] ^= username[i] * seed;
        seed *= A;
      }
      
      // mix with domain
      for (std::wstring::size_type i = 0;i < domain.length();i++) {
        gtalk_entropy[idx++ % 4] ^= domain[i] * seed;
        seed *= A;
      }
    }
    return bResult;
}

/** 
 *  
 *  Base16 decoder
 *
 */
void gtalk_decode(BYTE blob[], std::wstring input) {
    
    std::wstring alphabet = L"!\"#$%&'()*+,-./0";
    long seed = gtalk_entropy[0] | 1;
    long A = 69621;
    PBYTE p = blob;
    
    for (size_t i = 4;i < input.length();i += 2) {
      int c;
    
      c  = (alphabet.find_first_of(input.at(i + 0))) << 4;        
      c |= (alphabet.find_first_of(input.at(i + 1))) & 0x0f;
    
      *p++ = c - (seed & 0xff); 
      seed *= A;
    }
}

/**
 *
 *  Decrypts the DPAPI blob
 *  Returns size of decrypted data
 *
 */
DWORD gtalk_decrypt(BYTE password[], BYTE blob_data[], size_t blob_size) {
    DATA_BLOB DataIn, DataEntropy, DataOut;
    
    DataEntropy.cbData = sizeof(gtalk_entropy);
    DataEntropy.pbData = (BYTE*)gtalk_entropy;
    
    DataIn.cbData = blob_size;
    DataIn.pbData = blob_data;
    
    BOOL bResult = CryptUnprotectData(&DataIn, NULL, &DataEntropy, 
        NULL, NULL, 1, &DataOut);
    
    if (bResult) {
      memcpy(password, DataOut.pbData, DataOut.cbData);
      password[DataOut.cbData] = 0;
      LocalFree(DataOut.pbData);
    }
    return bResult ? DataOut.cbData : 0;
}

/**
 *
 *  Enumerate Google Talk Accounts under current user profile and decrypt.
 *
 */
void gtalk_dump(void) {
    HKEY hKey;
    std::wstring path = L"Software\\Google\\Google Talk\\Accounts";
  
    if (RegOpenKeyEx(HKEY_CURRENT_USER, path.c_str(),
        0, KEY_ENUMERATE_SUB_KEYS, &hKey) != ERROR_SUCCESS) {
      wprintf(L"  Unable to open \"HKEY_CURRENT_USER\\%s\"\n", path.c_str());
      return;
    }
    
    wprintf(L"  %-25s  %s\n", L"Username", L"Password");
    wprintf(L"  %-25s  %s\n", std::wstring(25, L'*').c_str(), 
        std::wstring(20, L'*').c_str());
    
    for (DWORD dwIndex = 0;;dwIndex++) {
      wchar_t key[1024];
      
      if (RegEnumKey(hKey, dwIndex, key, 1024) == ERROR_NO_MORE_ITEMS) {
        break;
      }
      
      wchar_t pw[1024];
      DWORD cbSize = 1024;
      
      if (SHGetValue(hKey, key, L"pw", 0, pw, &cbSize) != ERROR_SUCCESS) {
        continue;
      }
      BYTE blob[1024];
      BYTE passw[512];
      DWORD dwLen;
      INT iResult;
      
      gtalk_decode(blob, pw);
      
      if ((dwLen = gtalk_decrypt(passw, blob, cbSize / 2)) != 0) {
        wprintf(L"  %-25s  ", key);
        iResult = 0;
        if (IsTextUnicode(passw, dwLen, &iResult) != 0) {
          wprintf(L"%s\n", passw);
        } else {
          printf("%s\n", passw);
        }
      } else {
        wprintf(L"  Unable to decrypt password for %s\n", key);
      }
    }
    RegCloseKey(hKey);
}

int main(int argc, char *argv[]) {
    wprintf(L"\n\n  Google Talk Decoder v1.0"
          L"\n  Copyright (c) 2012 Kevin Devine\n\n");

    if (init_entropy()) {
      gtalk_dump();
    } else {
      wprintf(L"  Unable to initialize entropy\n");
    }
    wprintf(L"\nPress any key to continue . . .");
    fgetc(stdin);
    return 0;
}
