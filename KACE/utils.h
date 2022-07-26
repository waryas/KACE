#pragma once
#include <locale>
#include <string>

FORCEINLINE std::wstring UtilWidestringFromString(const std::string& str) {
    // gross but 3 lines
    std::wstring wret;
    wret.assign(str.begin(), str.end());
    return wret;
}

FORCEINLINE std::string UtilStringFromWidestring(const std::wstring& str) {
    // gross but 3 lines
    std::string ret;
    ret.assign(str.begin(), str.end());
    return ret;
}

FORCEINLINE VOID RtlInitUnicodeString(_Out_ PUNICODE_STRING DestinationString, _In_opt_ PCWSTR SourceString) {
    if (SourceString)
        DestinationString->MaximumLength = (DestinationString->Length = (USHORT)(wcslen(SourceString) * sizeof(WCHAR))) + sizeof(UNICODE_NULL);
    else
        DestinationString->MaximumLength = DestinationString->Length = 0;

    DestinationString->Buffer = (PWCH)malloc(DestinationString->MaximumLength);
    memset(DestinationString->Buffer, 0, DestinationString->MaximumLength);
    memcpy(DestinationString->Buffer, SourceString, DestinationString->MaximumLength);
}