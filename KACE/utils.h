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

#define InitializeListHead(ListHead) (\
     (ListHead)->Flink = (ListHead)->Blink = (ListHead))

#define IsListEmpty(ListHead) \
     ((ListHead)->Flink == (ListHead))



#define RemoveHeadList(ListHead) \
     (ListHead)->Flink;\
     {RemoveEntryList((ListHead)->Flink)}


#define RemoveTailList(ListHead) \
     (ListHead)->Blink;\
     {RemoveEntryList((ListHead)->Blink)}


#define RemoveEntryList(Entry) {\
     PLIST_ENTRY _EX_Blink;\
     PLIST_ENTRY _EX_Flink;\
     _EX_Flink = (Entry)->Flink;\
     _EX_Blink = (Entry)->Blink;\
     _EX_Blink->Flink = _EX_Flink;\
     _EX_Flink->Blink = _EX_Blink;\
     }



#define InsertTailList(ListHead,Entry) {\
     PLIST_ENTRY _EX_Blink;\
     PLIST_ENTRY _EX_ListHead;\
     _EX_ListHead = (ListHead);\
     _EX_Blink = _EX_ListHead->Blink;\
     (Entry)->Flink = _EX_ListHead;\
     (Entry)->Blink = _EX_Blink;\
     _EX_Blink->Flink = (Entry);\
     _EX_ListHead->Blink = (Entry);\
     }


#define InsertHeadList(ListHead,Entry) {\
     PLIST_ENTRY _EX_Flink;\
     PLIST_ENTRY _EX_ListHead;\
     _EX_ListHead = (ListHead);\
     _EX_Flink = _EX_ListHead->Flink;\
     (Entry)->Flink = _EX_Flink;\
     (Entry)->Blink = _EX_ListHead;\
     _EX_Flink->Blink = (Entry);\
     _EX_ListHead->Flink = (Entry);\
     }