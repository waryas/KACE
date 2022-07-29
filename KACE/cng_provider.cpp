#include <windows.h>
#include "provider.h"
#include "cng_provider.h"

namespace Provider::CNG {


	NTSTATUS h_BCryptOpenAlgorithmProvider(
		BCRYPT_ALG_HANDLE* phAlgorithm,
		LPCWSTR           pszAlgId,
		LPCWSTR           pszImplementation,
		ULONG             dwFlags
	) {

		auto ret = BCryptOpenAlgorithmProvider(phAlgorithm, pszAlgId, pszImplementation, dwFlags);
		return ret;
	}

	NTSTATUS h_BCryptGetProperty(
		BCRYPT_HANDLE hObject,
		LPCWSTR       pszProperty,
		PUCHAR        pbOutput,
		ULONG         cbOutput,
		ULONG* pcbResult,
		ULONG		  dwFlags
	) {
		auto ret = BCryptGetProperty(hObject, pszProperty, pbOutput, cbOutput, pcbResult, dwFlags);
		return ret;

	}

	NTSTATUS h_BCryptCreateHash(
		BCRYPT_ALG_HANDLE  hAlgorithm,
		BCRYPT_HASH_HANDLE* phHash,
		PUCHAR             pbHashObject,
		ULONG              cbHashObject,
		PUCHAR             pbSecret,
		ULONG              cbSecret,
		ULONG              dwFlags
	) {
		auto ret = BCryptCreateHash(hAlgorithm, phHash, pbHashObject, cbHashObject, pbSecret, cbSecret, dwFlags);
		return ret;
	}

	NTSTATUS h_BCryptHashData(
		BCRYPT_HASH_HANDLE hHash,
		PUCHAR             pbInput,
		ULONG              cbInput,
		ULONG              dwFlags
	) {
		auto ret = BCryptHashData(hHash, pbInput, cbInput, dwFlags);
		return ret;

	}

	NTSTATUS h_BCryptFinishHash(
		BCRYPT_HASH_HANDLE hHash,
		PUCHAR             pbOutput,
		ULONG              cbOutput,
		ULONG              dwFlags
	) {
		auto ret = BCryptFinishHash(hHash, pbOutput, cbOutput, dwFlags);
		return ret;
	}

	int Initialize() {
		Provider::AddFuncImpl("BCryptOpenAlgorithmProvider", h_BCryptOpenAlgorithmProvider);
		Provider::AddFuncImpl("BCryptGetProperty", h_BCryptGetProperty);
		Provider::AddFuncImpl("BCryptCreateHash", h_BCryptCreateHash);
		Provider::AddFuncImpl("BCryptHashData", h_BCryptHashData);
		Provider::AddFuncImpl("BCryptFinishHash", h_BCryptFinishHash);
		return 1;
	}


}