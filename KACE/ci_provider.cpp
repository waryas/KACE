#pragma once
#include <windows.h>
#include "provider.h"
#include "ntoskrnl_struct.h"
#include "ci_provider.h"

#include <Logger/Logger.h>
#include <PEMapper/pefile.h>

namespace Provider::CI {

	using proxyCall = NTSTATUS (__fastcall*)(...);


	static PolicyInfo lastValidCertificate = { 0 };
	static PolicyInfo lastTimeCertificate = { 0 };
	LARGE_INTEGER lastsigningTime = { 0 };
	bool done = false;

	NTSTATUS _stdcall h_CiCheckSignedFile(
		const PVOID digestBuffer,
		int digestSize,
		int digestIdentifier,
		const LPWIN_CERTIFICATE winCert,
		int sizeOfSecurityDirectory,
		PolicyInfo* policyInfoForSigner,
		LARGE_INTEGER* signingTime,
		PolicyInfo* policyInfoForTimestampingAuthority) {

		auto ci = PEFile::FindModule("ci.dll");
		auto rva = ci->GetExport("CiCheckSignedFile");
		
		proxyCall ciCheckSignedFile = (proxyCall)(ci->GetShadowBuffer() + rva);
		DWORD oldProtect;
		DWORD oldProtect2;
		VirtualProtect((PVOID)ci->GetMappedImageBase(), ci->GetVirtualSize(), PAGE_EXECUTE_READWRITE, &oldProtect);
		VirtualProtect((PVOID)ci->GetShadowBuffer(), ci->GetVirtualSize(), PAGE_EXECUTE_READWRITE, &oldProtect2);

		auto ret = ciCheckSignedFile(digestBuffer, digestSize, digestIdentifier, winCert, sizeOfSecurityDirectory, policyInfoForSigner, signingTime, policyInfoForTimestampingAuthority);
		VirtualProtect((PVOID)ci->GetShadowBuffer(), ci->GetVirtualSize(), oldProtect2, &oldProtect2);
		VirtualProtect((PVOID)ci->GetMappedImageBase(), ci->GetVirtualSize(), oldProtect, &oldProtect);
		
		if (!done) {
			done = true;
			memcpy(&lastValidCertificate, policyInfoForSigner, sizeof(PolicyInfo));
			memcpy(&lastsigningTime, signingTime, sizeof(LARGE_INTEGER));
			memcpy(&lastTimeCertificate, policyInfoForTimestampingAuthority, sizeof(PolicyInfo));
		}
		return 0;
	}


	PVOID _stdcall h_CiFreePolicyInfo(PolicyInfo* policyInfo) {
		auto ci = PEFile::FindModule("ci.dll");
		/*
		auto rva = ci->GetExport("CiFreePolicyInfo");

		proxyCall CiFreePolicyInfo = (proxyCall)(ci->GetShadowBuffer() + rva);
		DWORD oldProtect;
		DWORD oldProtect2;
		VirtualProtect((PVOID)ci->GetMappedImageBase(), ci->GetVirtualSize(), PAGE_EXECUTE_READWRITE, &oldProtect);
		VirtualProtect((PVOID)ci->GetShadowBuffer(), ci->GetVirtualSize(), PAGE_EXECUTE_READWRITE, &oldProtect2);

		auto ret = CiFreePolicyInfo(policyInfo);
		VirtualProtect((PVOID)ci->GetShadowBuffer(), ci->GetVirtualSize(), oldProtect2, &oldProtect2);
		VirtualProtect((PVOID)ci->GetMappedImageBase(), ci->GetVirtualSize(), oldProtect, &oldProtect);
		*/
		return (PVOID)0;
	}


	NTSTATUS _stdcall h_CiValidateFileObject(
		struct _FILE_OBJECT* fileObject,
		int a2,
		int a3,
		PolicyInfo* policyInfoForSigner,
		PolicyInfo* policyInfoForTimestampingAuthority,
		LARGE_INTEGER* signingTime,
		BYTE* digestBuffer,
		int* digestSize,
		int* digestIdentifier
	) {
		auto ci = PEFile::FindModule("ci.dll");
		DebugBreak();
		return 0;
	}

	NTSTATUS h_CiVerifyHashInCatalog(
			_In_ PVOID                  Hash,
			_In_ UINT32                 HashSize,
			_In_ ALG_ID                 HashAlgId,
			_In_ BOOLEAN                IsReloadCatalogs,
			_In_ UINT32                 Always0,                // This is for IsReloadCatalogs, Always0 != 0 ? 16 : 24;
			_In_ UINT32                 Always2007F,
			_Out_ PolicyInfo* PolicyInfos,
			_Out_opt_ UNICODE_STRING* CatalogName,
			_Out_ LARGE_INTEGER* SigningTime,
			_Out_ PolicyInfo* TimeStampPolicyInfo
		)
	{
		/*
		auto ci = PEFile::FindModule("ci.dll");
		auto rva = ci->GetExport("CiVerifyHashInCatalog");

		proxyCall CiVerifyHashInCatalog = (proxyCall)(ci->GetShadowBuffer() + rva);
		DWORD oldProtect;
		DWORD oldProtect2;
		VirtualProtect((PVOID)ci->GetMappedImageBase(), ci->GetVirtualSize(), PAGE_EXECUTE_READWRITE, &oldProtect);
		VirtualProtect((PVOID)ci->GetShadowBuffer(), ci->GetVirtualSize(), PAGE_EXECUTE_READWRITE, &oldProtect2);

		auto ret = CiVerifyHashInCatalog(Hash, HashSize, HashAlgId, IsReloadCatalogs, Always0, Always2007F, PolicyInfos, CatalogName, SigningTime, TimeStampPolicyInfo);
		VirtualProtect((PVOID)ci->GetShadowBuffer(), ci->GetVirtualSize(), oldProtect2, &oldProtect2);
		VirtualProtect((PVOID)ci->GetMappedImageBase(), ci->GetVirtualSize(), oldProtect, &oldProtect);
		*/
		memcpy(PolicyInfos, &lastValidCertificate, sizeof(lastValidCertificate));
		memcpy(TimeStampPolicyInfo, &lastTimeCertificate, sizeof(lastTimeCertificate));
		memcpy(SigningTime, &lastsigningTime, sizeof(LARGE_INTEGER));

		return 0x0;
	}


	int Initialize() {

		//auto ci = PEFile::Open("c:\\emu\\ci.dll", "ci.dll");
		//ci->ResolveImport();

		Provider::AddFuncImpl("CiCheckSignedFile", h_CiCheckSignedFile);
		Provider::AddFuncImpl("CiVerifyHashInCatalog", h_CiVerifyHashInCatalog);
		Provider::AddFuncImpl("CiFreePolicyInfo", h_CiFreePolicyInfo);
		Provider::AddFuncImpl("CiValidateFileObject", h_CiValidateFileObject);
		
		return 0;
	}
}