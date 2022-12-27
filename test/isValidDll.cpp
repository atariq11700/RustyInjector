#include <iostream>
#include <windows.h>
#include <TlHelp32.h>
#include <string>

typedef BYTE* BYTEARRAY;

BYTEARRAY isValidDll(std::string dllpath);

int main() {
    isValidDll("test/dlltobeinjected.dll");
}


BYTEARRAY isValidDll(std::string dllpath) {
    const char* szDllPath = dllpath.c_str();

    printf("Checking the validity of %s\n", szDllPath);

    //check that the dll file exists
    if (!GetFileAttributesA(szDllPath)) {
        printf("Dll file %s doesn't exist\n", szDllPath);
        return nullptr;
    }

    //open the dll and check the size
    FILE* dllfile;
    fopen_s(&dllfile, szDllPath, "rb");

    if (!dllfile) {
        printf("Failed to open the dll file\n");
        fclose(dllfile);
        return nullptr;
    } else {
        printf("Opened the dll file\n");
    }

    fseek(dllfile, 0, SEEK_END);
    int filesize = ftell(dllfile);
    fseek(dllfile, 0, SEEK_SET);

    if (filesize < 0x1000) {
        printf("Dll has invalid filesize\n");
        fclose(dllfile);
        return nullptr;
    } else {
        printf("Dll has a valid size\n");
    }

    //read the dll file into a byte buffer
    BYTE* pDllBinaryData = new BYTE[filesize];
    if (!pDllBinaryData) {
        printf("Failed to allocate space for dll\n");
        fclose(dllfile);
        delete[] pDllBinaryData;
        return nullptr;
    } else {
        printf("Allocated %d bytes for the dll\n", filesize);
    }
    
    if (fread(pDllBinaryData, filesize, 1, dllfile) != 1) {
        printf("Failed to read the dll \n");
        fclose(dllfile);
        delete[] pDllBinaryData;
        return nullptr;
    } else {
        printf("Read the dll file\n");
        fclose(dllfile);
    }

    //check for MZ bytes
    if (((IMAGE_DOS_HEADER*)pDllBinaryData)->e_magic != IMAGE_DOS_SIGNATURE) {
        printf("Dll file is not a valid pe image\n");
        delete[] pDllBinaryData;
    }  

    IMAGE_NT_HEADERS*       pDllNtHeader    =   (IMAGE_NT_HEADERS*)(pDllBinaryData + ((IMAGE_DOS_HEADER*)pDllBinaryData)->e_lfanew);
    IMAGE_OPTIONAL_HEADER*  pDllOptHeader   =   (IMAGE_OPTIONAL_HEADER*)&pDllNtHeader->OptionalHeader;
    IMAGE_FILE_HEADER*      pDllFileHeader  =   (IMAGE_FILE_HEADER*)&pDllNtHeader->FileHeader;


#if _WIN64 == 1
    if (pDllFileHeader->Machine != IMAGE_FILE_MACHINE_AMD64) {
        printf("Injector is running as 64bit and the dll is not 64bit\n");
        delete[] pDllBinaryData;
        return nullptr;
    }
#elif _WIN32 == 1
    if (pDllFileHeader->Machine != IMAGE_FILE_MACHINE_I386) {
        printf("Injector is running as 32bit and the dll is not 32bit\n");
        delete[] pDllBinaryData;
        return nullptr;
    }
#else
    printf("Injector compiled for an unknown architecture. Please make sure to compile for either x86 or x64 and define the respective _WIN64 or _WIN32 macro\n");
    delete[] pDllBinaryData;
    return nullptr;
#endif

    printf("Dll is valid\n");


    printf("Some bytes\n");
    for (int i = 0; i < 10; i++) {
        printf("%d ", *(pDllBinaryData + i));
    }
    printf("\n");
    printf("Nt sig: %lld\n", pDllNtHeader->Signature);
    BYTE f = pDllOptHeader->NumberOfRvaAndSizes;
    BYTE g = pDllOptHeader->DllCharacteristics;
    BYTE h = pDllFileHeader->Machine;

    printf("%lld\n",f);
    printf("%lld\n",g);
    printf("%lld\n",h);


    return pDllBinaryData;

}