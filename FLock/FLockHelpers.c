//
// Project:
//
//		Data Guard FLock driver.
//
// Author:
//
//		Burlutsky Stanislav
//		burluckij@gmail.com
//

#include "flock.h"


extern ULONG gTraceFlags;


static const WCHAR* g_UnicodeFlockMetaName = FLOCK_META_NAME;


BOOLEAN FLockFltReadFirstMetaWithGetFilePath(
	__in PFLT_FILTER	_filter,
	__in PFLT_INSTANCE  _instance,
	__in PFLT_CALLBACK_DATA _fltData,
	__out PFLOCK_META _readMeta,
	__out_opt  PUNICODE_STRING _outFilePath,
	__out_opt NTSTATUS* _errorCode
	)
{
	UNICODE_STRING filePath;
	RtlZeroMemory(&filePath, sizeof(filePath));

	if (!(_fltData || _instance || _filter || _readMeta)){
		SETPTR(_errorCode, STATUS_INVALID_ADDRESS);
		return FALSE;
	}

	BOOLEAN result = FLockFltGetPath(_filter, _instance, _fltData, &filePath, _errorCode);

	if (result)
	{
		result = FLockFltOpenAndReadFirstMeta(_filter, _instance, &filePath, _readMeta, _errorCode);
		
		if (result)
		{
			//
			// Copy just parsed file path to '_outFilePath' if it was passed to this function.
			//
			if (_outFilePath)
			{
				_outFilePath->Buffer = filePath.Buffer;
				_outFilePath->Length = filePath.Length;
				_outFilePath->MaximumLength = filePath.MaximumLength;
			}
			else
			{
				//
				// Free memory if it is not necessary to pass file path string.
				//
				if (filePath.Buffer)
				{
					ExFreePool(filePath.Buffer);
				}
			}
		}
	}

	return result;
}

BOOLEAN FLockFltGetPath(
	__in PFLT_FILTER	_filter,
	__in PFLT_INSTANCE  _instance,
	__in PFLT_CALLBACK_DATA _fltData,
	__out PUNICODE_STRING _filePath,
	__out_opt NTSTATUS* _errorCode
	)
{
	PAGED_CODE();

	BOOLEAN result = FALSE;
	PFLT_FILE_NAME_INFORMATION	nameInfo = NULL;
	UNICODE_STRING filePathToExplore = { 0 };

	if (!(_fltData || _instance || _filter || _filePath)){
		SETPTR(_errorCode, STATUS_INVALID_ADDRESS);
		return FALSE;
	}

	NTSTATUS status = FltGetFileNameInformation(_fltData, (FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_ALWAYS_ALLOW_CACHE_LOOKUP), &nameInfo);

	if (!NT_SUCCESS(status))
	{
		status = FltGetFileNameInformation(_fltData, (FLT_FILE_NAME_OPENED | FLT_FILE_NAME_QUERY_ALWAYS_ALLOW_CACHE_LOOKUP), &nameInfo);

		if (!NT_SUCCESS(status))
		{
			PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s: error after second call FltGetFileNameInformation(..), status is 0x%x\n", __FUNCTION__, status));

			SETPTR(_errorCode, status);
			return FALSE;
		}
	}

	if (NT_SUCCESS(status)) {
		status = FltParseFileNameInformation(nameInfo);
	} else {
		goto _exit_release_filename;
	}

	if (!NT_SUCCESS(status))
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s: error call FltParseFileNameInformation(..), status is 0x%x\n", __FUNCTION__, status));

		SETPTR(_errorCode, status);
		goto _exit_release_filename;
	}

	if (nameInfo->Volume.Length == 0)
	{
		SETPTR(_errorCode, STATUS_NOT_FOUND); // Volume not found.
		goto _exit_release_filename;
	}

	//
	// Prepare - buffer for UNICODE_STRING with file path.
	//

	DWORD needSize = nameInfo->Volume.Length + nameInfo->ParentDir.Length + nameInfo->FinalComponent.Length + nameInfo->Extension.Length + 128; /*I hope the string is not bigger.*/
	WCHAR* pStrPathBuffer = ExAllocatePool(PagedPool, needSize);

	if (pStrPathBuffer == NULL)
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s: error call ExAllocatePool(%d), status is 0x%x\n", __FUNCTION__, needSize, status));

		SETPTR(_errorCode, STATUS_INSUFFICIENT_RESOURCES);
		goto _exit_release_filename;
	}

	RtlZeroMemory(pStrPathBuffer, needSize);
	RtlInitEmptyUnicodeString(&filePathToExplore, pStrPathBuffer, needSize);

	// \Device\HarddiskVolume1\Windows\System32\notepad.exe

	RtlCopyUnicodeString(&filePathToExplore, &nameInfo->Volume);

	if (nameInfo->NamesParsed & FLTFL_FILE_NAME_PARSED_PARENT_DIR)
	{
		status = RtlAppendUnicodeStringToString(&filePathToExplore, &nameInfo->ParentDir);

		if (!NT_SUCCESS(status)) {
			SETPTR(_errorCode, STATUS_UNSUCCESSFUL);
			goto _exit_and_free;
		}
	}

	if (nameInfo->NamesParsed & FLTFL_FILE_NAME_PARSED_FINAL_COMPONENT)
	{
		status = RtlAppendUnicodeStringToString(&filePathToExplore, &nameInfo->FinalComponent);

		if (!NT_SUCCESS(status)){
			SETPTR(_errorCode, STATUS_UNSUCCESSFUL);
			goto _exit_and_free;
		}
	}

	//
	// Return results in _filePath, do not forget to free memory of '_filePath->Buffer' through ExFreePool.
	//

	_filePath->Buffer = filePathToExplore.Buffer;
	_filePath->Length = filePathToExplore.Length;
	_filePath->MaximumLength = filePathToExplore.MaximumLength;

	FltReleaseFileNameInformation(nameInfo);
	return TRUE;

_exit_and_free:
	ExFreePool(pStrPathBuffer);

_exit_release_filename:
	FltReleaseFileNameInformation(nameInfo);

	return result;
}


// BOOLEAN FLockFltSearchFirstMetaPath(
// 	__in PFLT_FILTER	_filter,
// 	__in PFLT_INSTANCE  _instance,
// 	__in PFLT_CALLBACK_DATA _fltData,
// 	__in PCFLT_RELATED_OBJECTS FltObjects,
// 	__in BOOLEAN _skipFirstFile,
// 	__out PFLOCK_META _readMetaInfo,
// 	__out PUNICODE_STRING _unused,
// 	__out_opt NTSTATUS* _errorCode
// 	)
// {
// 	PAGED_CODE();
// 
// 	BOOLEAN result = FALSE;
// 	FLOCK_META fm = { 0 };
// 	PFLT_FILE_NAME_INFORMATION	nameInfo = NULL;
// 	UNICODE_STRING filePathToExplore = { 0 };
// 	IO_STATUS_BLOCK ioStatus = { 0 };
// 	OBJECT_ATTRIBUTES oaFile = { 0 };
// 
// 	//
// 	// Get file path info.
// 	//
// 
// 	NTSTATUS status = FltGetFileNameInformation(_fltData, (FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_ALWAYS_ALLOW_CACHE_LOOKUP), &nameInfo);
// 
// 	if (!NT_SUCCESS(status))
// 	{
// 		status = FltGetFileNameInformation(_fltData, (FLT_FILE_NAME_OPENED | FLT_FILE_NAME_QUERY_ALWAYS_ALLOW_CACHE_LOOKUP), &nameInfo);
// 
// 		if (!NT_SUCCESS(status))
// 		{
// 			PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s: error after second call FltGetFileNameInformation(..), status is 0x%x\n", __FUNCTION__, status));
// 
// 			SETPTR(_errorCode, status);
// 			return FALSE;
// 		}
// 	}
// 
// 	if (NT_SUCCESS(status)) {
// 		status = FltParseFileNameInformation(nameInfo);
// 	} else {
// 		goto _exit_release_filename;
// 	}
// 
// 	if ( !NT_SUCCESS(status) )
// 	{
// 		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s: error call FltParseFileNameInformation(..), status is 0x%x\n", __FUNCTION__, status));
// 
// 		SETPTR(_errorCode, status);
// 		goto _exit_release_filename;
// 	}
// 
// 	//
// 	// Prepare - where to start searching - parent directory or from the file?
// 	//
// 
// 	DWORD needSize = nameInfo->Volume.Length + nameInfo->Extension.Length + nameInfo->ParentDir.Length + nameInfo->FinalComponent.Length + 512; /*I hope the string is not bigger.*/
// 	WCHAR* pStrPathBuffer = ExAllocatePool(PagedPool, needSize);
// 	WCHAR* rootDirEnd = NULL;
// 	DWORD rootDirEndPos = 0;
// 
// 	if (pStrPathBuffer == NULL)
// 	{
// 		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s: error call ExAllocatePool(%d), status is 0x%x\n", __FUNCTION__, needSize, status));
// 
// 		SETPTR(_errorCode, STATUS_INSUFFICIENT_RESOURCES);
// 		goto _exit_release_filename;
// 	}
// 
// 	//
// 	// Oh, the string was created!
// 	//
// 	RtlInitEmptyUnicodeString(&filePathToExplore, pStrPathBuffer, needSize);
// 
// 	//
// 	// Volume at first!
// 	//
// 
// 	// \Device\HarddiskVolume1\Windows\System32\dllhost.exe
// 	// \??\C:\Windows\System32\dllhost.exe
// 
// 	if (nameInfo->Volume.Length){
// 		RtlCopyUnicodeString(&filePathToExplore, &nameInfo->Volume);
// 
// 		rootDirEnd = (PWCHAR)(pStrPathBuffer + WCHAR_COUNT(nameInfo->Volume.Length));
// 		rootDirEndPos = WCHAR_COUNT(nameInfo->Volume.Length);
// 	}
// 
// // 	if (filePathToExplore.Length)
// // 	{
// // 		if (filePathToExplore.Buffer[WCHAR_COUNT(filePathToExplore.Length) - WCHAR_LEN(1)] != L'\\') {
// // 			status = RtlAppendUnicodeToString(&filePathToExplore, L"\\");
// // 		}
// // 	}
// 
// 	//
// 	// File path follows after volume.
// 	//
// 
// 	if (nameInfo->NamesParsed & FLTFL_FILE_NAME_PARSED_PARENT_DIR)
// 	{
// 		RtlAppendUnicodeStringToString(&filePathToExplore, &nameInfo->ParentDir);
// 	}
// 	else
// 	{
// 		// Have no information about parent directory.
// 		// ...
// 	}
// 
// 	//
// 	// Does it need add file name?
// 	//
// 	if ( !_skipFirstFile )
// 	{
// 		// Add '\' symbol before to add file name with extension.
// 		if (nameInfo->ParentDir.Length)
// 		{
// // 			if (nameInfo->ParentDir.Buffer[WCHAR_COUNT(nameInfo->ParentDir.Length) - WCHAR_LEN(1)] != L'\\')
// // 			{
// // 				status = RtlAppendUnicodeToString(&filePathToExplore, L"\\");
// // 			}
// 		}
// 
// 		if (NT_SUCCESS(status))
// 		{
// 			if (nameInfo->NamesParsed & FLTFL_FILE_NAME_PARSED_FINAL_COMPONENT)
// 			{
// 				status = RtlAppendUnicodeStringToString(&filePathToExplore, &nameInfo->FinalComponent);
// 
// // 				if (NT_SUCCESS(status))
// // 				{
// // 					if (nameInfo->NamesParsed & FLTFL_FILE_NAME_PARSED_EXTENSION)
// // 					{
// // 						status = RtlAppendUnicodeStringToString(&filePathToExplore, &nameInfo->Extension);
// // 					}
// // 				}
// 			}
// 		}
// 	}
// 
// 	if (!NT_SUCCESS(status))
// 	{
// 		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s: error - there was a problem while we parsed file path 0x%x\n", __FUNCTION__, status));
// 
// 		SETPTR(_errorCode, status);
// 		goto _exit_and_free;
// 	}
// 
// 	//
// 	// Oh, Yeah! Here we have file path and can start searching FLock-meta.
// 	//
// 
// 	PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s: Success - ready to handle file path %wZ\n", __FUNCTION__, &filePathToExplore));
// 
// 	//
// 	// Go through all parent paths.
// 	//
// 
// 	// \Device\HarddiskVolume1\Windows\System32\dllhost.exe
// 	// \Device\HarddiskVolume1\Windows\System32
// 	// \Device\HarddiskVolume1\Windows
// 	// \Device\HarddiskVolume1 << Root achieved.
// 
// 	// \??\C:\Windows\System32\dllhost.exe
// 
// 	// Verify!
// 	// FLock ...
// 	//
// 
// 	status = RtlAppendUnicodeToString(&filePathToExplore, L"\\");
// 
// 	for (int delPos = WCHAR_COUNT(filePathToExplore.Length); delPos > rootDirEndPos;)
// 	{
// 		UNICODE_STRING partPath = { 0 };
// 
// 		delPos--;
// 
// 		WCHAR w = L'\\';
// 		BOOLEAN itWasDelimeter = ( (((WCHAR*)filePathToExplore.Buffer)[delPos /*- 1*/]) == w/*L'\\'*/);
// 
// 		//
// 		// Cut size of the file path.
// 		//
// 
// 		//filePathToExplore.Buffer[delPos] = L'\0';
// 		(((WCHAR*)filePathToExplore.Buffer)[delPos /*- 1*/]) = 0;
// 		//(((WCHAR*)filePathToExplore.Buffer)[delPos + 1]) = 0;
// 		filePathToExplore.Length -= WCHAR_LEN(1);
// 		// delPos--;
// 
// 		if (itWasDelimeter)
// 		{
// 			PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s: Delimiter was found -  %wZ, length is %d, delPos %d, rootEndPos %d\n",
// 				__FUNCTION__, &filePathToExplore, filePathToExplore.Length, delPos, rootDirEndPos));
// 
// 
// // 			result = FLockFltOpenAndReadFirstMeta(_filter, _instance, _fltData, &filePathToExplore, &fm, &status);
// // 
// // 
// // 			if (result){
// // 				PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s: !success - FLock-meta was found in %wZ\n", __FUNCTION__, &filePathToExplore));
// // 
// // 				RtlCopyMemory(_readMetaInfo, &fm, sizeof(FLOCK_META));
// // 				break;
// // 			}
// // 			else
// // 			{
// // 				PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s: failed - FLock-meta not found in %wZ, status is 0x%x\n", __FUNCTION__, &filePathToExplore, status));
// // 				SETPTR(_errorCode, status);
// // 			}
// 
// 
// 			if (delPos <= rootDirEndPos) // volume root
// 			{
// 				PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s: Ignore reading EAs from volume - FLock-meta not found in %wZ\n", __FUNCTION__, &filePathToExplore));
// 			}
// 			else // It's just a path.
// 			{
// 				result = FLockFltOpenAndReadFirstMeta(_filter, _instance, _fltData, &filePathToExplore, &fm, &status);
// 
// 				if (result){
// 					PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s: !success - FLock-meta was found in %wZ\n", __FUNCTION__, &filePathToExplore));
// 
// 					RtlCopyMemory(_readMetaInfo, &fm, sizeof(FLOCK_META));
// 					break;
// 				}
// 				else
// 				{
// 					PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s: failed - FLock-meta not found in %wZ, status is 0x%x\n", __FUNCTION__, &filePathToExplore, status));
// 					SETPTR(_errorCode, status);
// 				}
// 			}
// 
// 
// // 			if (delPos <= rootDirEndPos) { // Root achieved.
// // 				result = FLockFltOpenAndReadFirstMeta(_filter, _instance, _fltData, &filePathToExplore, &fm, &status);
// // 				if (result == TRUE){
// // 					RtlCopyMemory(_readMetaInfo, &fm, sizeof(FLOCK_META));
// // 					break;
// // 				}
// // 			} else // It's just a path.
// // 			{
// // 				result = FLockFltOpenAndReadFirstMeta(_filter, _instance, _fltData, &filePathToExplore, &fm, &status);
// // 				if (result == TRUE){
// // 					RtlCopyMemory(_readMetaInfo, &fm, sizeof(FLOCK_META));
// // 					break;
// // 				}
// // 			}
// 
// 
// 		}
// 	}
// 
// _exit_and_free:
// 	ExFreePool(pStrPathBuffer);
// 
// _exit_release_filename:
// 	FltReleaseFileNameInformation(nameInfo);
// 	
// 	return result;
// }


BOOLEAN FLockFltOpenAndReadFirstMeta(
	__in PFLT_FILTER	_filter,
	__in PFLT_INSTANCE  _instance,
	__in PUNICODE_STRING _filePath,
	__out PFLOCK_META _readMetaInfo,
	__out_opt NTSTATUS* _errorCode
	)
{
	PAGED_CODE();

	BOOLEAN result = FALSE;
	HANDLE hFile;
	PFILE_OBJECT pFileObject = NULL;
	IO_STATUS_BLOCK ioStatus = { 0 };
	OBJECT_ATTRIBUTES oaFile = { 0 };

	BOOLEAN allArgumentsPassed = (_readMetaInfo && _instance && _filter && _filePath);
	if (!allArgumentsPassed){
		SETPTR(_errorCode, STATUS_INVALID_ADDRESS);
		return FALSE;
	}

	InitializeObjectAttributes(&oaFile, _filePath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

	NTSTATUS status = FltCreateFile(
		_filter,
		_instance,
		&hFile,
		FILE_READ_EA /* | FILE_READ_ATTRIBUTES*/,
		&oaFile,
		&ioStatus,
		NULL, // AllocationSize
		FILE_ATTRIBUTE_NORMAL, // FileAttributes
		FILE_SHARE_READ, // Not Exclusive share access
		FILE_OPEN,
		0, //FILE_DIRECTORY_FILE for directory
		NULL, // EaBuffer
		0, // EaLength
		IO_IGNORE_SHARE_ACCESS_CHECK
		);

	if (NT_SUCCESS(status))
	{
		//PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: Success - %wZ was opened, status code is 0x%x\n", __FUNCTION__, _filePath, status));

		status = ObReferenceObjectByHandle(hFile, STANDARD_RIGHTS_READ, *IoFileObjectType, KernelMode, &pFileObject, NULL);

		if (NT_SUCCESS(status))
		{
			result = FLockFltReadFirstMeta(_instance, pFileObject, _readMetaInfo, _errorCode);

			//
			// We can't use FLockReadFastFirstMeta(..) because in that case we receives IRP_MJ_QUERY_EA.
			// It is not necessary to spend our time on handling IRP_MJ_QUERY_EA.
			//
			//result = FLockReadFastFirstMeta(hFile, _readMetaInfo, _errorCode);
		}
		else
		{
			PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: failed - can't get FILE_OBJECT by handle for %wZ, status code is 0x%x\n",
				__FUNCTION__, _filePath, status));
		}

		ZwClose(hFile);
	}
	else
	{
		//PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: failed - can't open file %wZ, status code is 0x%x\n", __FUNCTION__, _filePath, status));

		SETPTR(_errorCode, status);
	}

	return result;
}

//
// Call that function on < DISPATCH_LEVEL !
//
BOOLEAN FLockFltOpenAndReadFirstMeta0(
	__in PFLT_FILTER	_filter,
	__in PFLT_INSTANCE  _instance,
	__in PFLT_CALLBACK_DATA _fltData,
	__out PFLOCK_META _readMetaInfo,
	__out_opt NTSTATUS* _errorCode
	)
{
	BOOLEAN result = FALSE;
	PFLT_FILE_NAME_INFORMATION	nameInfo = NULL;
	NTSTATUS status;
	USHORT charsCounter = 0;
	HANDLE hFile;
	UNICODE_STRING filePathToOpen = {0};
	IO_STATUS_BLOCK ioStatus = { 0 };
	OBJECT_ATTRIBUTES oaFile = { 0 };

	PAGED_CODE();


	status = FltGetFileNameInformation(_fltData, (FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_ALWAYS_ALLOW_CACHE_LOOKUP), &nameInfo);

	if (!NT_SUCCESS(status))
	{
		status = FltGetFileNameInformation(_fltData, (FLT_FILE_NAME_OPENED | FLT_FILE_NAME_QUERY_ALWAYS_ALLOW_CACHE_LOOKUP), &nameInfo);

		if (!NT_SUCCESS(status))
		{
			//PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FsFilter! %s: error while get name.\n", __FUNCTION__ ));

			SETPTR(_errorCode, status);

			return FALSE;
		}
	}

	//
	// We have name to open and now can open that file by name.
	//

	// ...
	//


	// RtlInitUnicodeString(&usFilePath, _filePath);

	InitializeObjectAttributes(&oaFile, &filePathToOpen, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);


	status = FltCreateFile(
		_filter,
		_instance,
		&hFile,
		FILE_READ_EA /* | FILE_READ_ATTRIBUTES*/,
		&oaFile,
		&ioStatus,
		NULL, // AllocationSize
		FILE_ATTRIBUTE_NORMAL, // FileAttributes
		FILE_SHARE_READ, // Not Exclusive share access
		FILE_OPEN,
		0, //FILE_DIRECTORY_FILE for directory
		NULL, // EaBuffer
		0, // EaLength
		IO_IGNORE_SHARE_ACCESS_CHECK
		);

	if (NT_SUCCESS(status))
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: Success - %wZ was opened, status code is 0x%x (%d)\n", __FUNCTION__, &filePathToOpen, status, status));

		result = FLockReadFastFirstMeta(hFile, _readMetaInfo, &status);

		ZwClose(hFile);
	}
	else
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: failed - can't open file %wZ, status code is 0x%x (%d)\n", __FUNCTION__, &filePathToOpen, status, status));

		SETPTR(_errorCode, status);
	}

	return result;
}


BOOLEAN FLockFltReadFirstMeta(
	__in PFLT_INSTANCE _instance,
	__in PFILE_OBJECT  _fileObject,
	__out PFLOCK_META _readMetaInfo,
	__out NTSTATUS* _errorCode
	)
{
	BOOLEAN result = FALSE;
	NTSTATUS status = STATUS_NOT_FOUND;
	UCHAR flockMetaSignatureBuffer[16] = FLOCK_META_SIGNATURE;

	const DWORD eaSize = sizeof(FILE_FULL_EA_INFORMATION) + FLOCK_META_NAME_SIZE + sizeof(FLOCK_META);
	UCHAR metaBuffer[sizeof(FILE_FULL_EA_INFORMATION) + FLOCK_META_NAME_SIZE + sizeof(FLOCK_META)] = { 0 };
	PFILE_FULL_EA_INFORMATION pEa = (PFILE_FULL_EA_INFORMATION)metaBuffer;

	//
	// Prepare FILE_GET_EA_INFORMATION structure for the future searching.
	//

	DWORD cbRead = 0;
	DWORD srchEaSize = sizeof(FILE_GET_EA_INFORMATION) + FLOCK_META_NAME_SIZE;
	UCHAR srchEAsBuffer[sizeof(FILE_GET_EA_INFORMATION) + FLOCK_META_NAME_SIZE] = { 0 };
	PFILE_GET_EA_INFORMATION pGetEaInfo = (PFILE_GET_EA_INFORMATION)srchEAsBuffer;

	pGetEaInfo->NextEntryOffset = 0;
	pGetEaInfo->EaNameLength = FLOCK_META_NAME_SIZE;
	memcpy(pGetEaInfo->EaName, FLOCK_META_NAME, FLOCK_META_NAME_SIZE);

	//if ( ! (_readMetaInfo || _instance || _fileObject) ){
	
	BOOLEAN allArgsPassed = (_readMetaInfo && _instance && _fileObject);
	if (!allArgsPassed)
	{
		SETPTR(_errorCode, STATUS_INVALID_ADDRESS);
		return FALSE;
	}

	SETPTR(_errorCode, STATUS_NOT_FOUND);

	//
	// That function should be called at PASSIVE_LEVEL. Be Careful! 
	//
	status = FltQueryEaFile(_instance, _fileObject, metaBuffer, sizeof(metaBuffer), TRUE, pGetEaInfo, srchEaSize, NULL, TRUE, &cbRead);

	//
	// Handle results.
	//

	if (status == STATUS_EAS_NOT_SUPPORTED)
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: failed - EAs not supported on the file system, status code is 0x%x (%d)\n", __FUNCTION__, status, status));
		SETPTR(_errorCode, status);
	}
	else if (status == STATUS_INSUFFICIENT_RESOURCES) // It's not going to happen, but who knows.
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: failed - need more memory (current size is %d), status code is 0x%x (%d)\n", __FUNCTION__, srchEaSize, status, status));
		SETPTR(_errorCode, status);
	}
	else if (status == STATUS_NO_EAS_ON_FILE)
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: failed - the file has no EAs, status code is 0x%x (%d)\n", __FUNCTION__, status, status));
		SETPTR(_errorCode, status);
	}
	else if (NT_SUCCESS(status))
	{
		// PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: Ready to find - FLock's meta \n", __FUNCTION__));

		// Perform additional checks.
		if (pEa->EaNameLength == FLOCK_META_NAME_SIZE && (pEa->EaValueLength >= sizeof(FLOCK_META)))
		{
			PCHAR eaName = pEa->EaName;
			PVOID eaValue = pEa->EaName + (pEa->EaNameLength + 1);

			BOOLEAN metaFound = memcmp(eaName, FLOCK_META_NAME, FLOCK_META_NAME_SIZE) == 0;

			if (metaFound == TRUE)
			{
				PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: success - FLock meta found.\n", __FUNCTION__));

				PFLOCK_META metaInformation = (PFLOCK_META)eaValue;

				//
				// Second validation it's a verification of the hard-coded meta-information signature.
				//
				BOOLEAN valid = memcmp(metaInformation->signature, flockMetaSignatureBuffer, sizeof(flockMetaSignatureBuffer)) == 0;

				if (valid)
				{
					PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: success - FLock meta was read and validated.\n", __FUNCTION__));
					
					SETPTR(_errorCode, STATUS_SUCCESS);
					result = TRUE;

					RtlCopyMemory(_readMetaInfo, metaInformation, sizeof(FLOCK_META));
				}
				else
				{
					PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: failed - bad FLock meta-signature\n", __FUNCTION__));
					SETPTR(_errorCode, STATUS_BAD_DATA);
				}
			}
			else
			{
				PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: error - just read FLock meta has invalid name attribute.\n", __FUNCTION__));
				SETPTR(_errorCode, STATUS_BAD_DATA);
			}
		}
		else
		{
// 			PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: warning - just read FLock meta is incorrect. name is %d bytes, value is %d bytes.\n",
// 				__FUNCTION__,
// 				pEa->EaNameLength,
// 				pEa->EaValueLength));

			SETPTR(_errorCode, STATUS_BAD_DATA);
		}
	}
	else
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: failed - can't get EAs, status code is 0x%x (%d)\n", __FUNCTION__, status, status));
		SETPTR(_errorCode, status);
	}

	return result;
}

BOOLEAN FLockFltWriteFlockMeta(
	__in PFLT_INSTANCE _instance,
	__in PFILE_OBJECT  _fileObject,
	__in PFLOCK_META _metaInfo,
	__out NTSTATUS* _errorCode
	)
{
	BOOLEAN allArgumentsPassed = (_instance && _fileObject && _metaInfo);
	if (!allArgumentsPassed)
	{
		SETPTR(_errorCode, STATUS_INVALID_ADDRESS);
		return FALSE;
	}

	CHAR eaData[sizeof(FILE_FULL_EA_INFORMATION) + FLOCK_META_NAME_SIZE + sizeof(FLOCK_META)];
	RtlZeroMemory(eaData, sizeof(eaData));

	PFILE_FULL_EA_INFORMATION pEa = (PFILE_FULL_EA_INFORMATION)eaData;
	pEa->NextEntryOffset = 0;
	pEa->Flags = 0;
	pEa->EaValueLength = sizeof(FLOCK_META);
	pEa->EaNameLength = FLOCK_META_NAME_SIZE;

	PUCHAR pEaName = (PUCHAR)pEa->EaName;
	PUCHAR pEaValue = pEaName + FLOCK_META_NAME_SIZE + 1 /* last zero symbol */;

	memcpy(pEaName, FLOCK_META_NAME, FLOCK_META_NAME_SIZE);
	memcpy(pEaValue, _metaInfo, sizeof(FLOCK_META));

	NTSTATUS status = FltSetEaFile(_instance, _fileObject, eaData, sizeof(eaData));
	if (NT_SUCCESS(status))
	{
		return TRUE;
	}
	else
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: failed - couldn't write flock-meta, status code is 0x%x\n", __FUNCTION__, status));

		SETPTR(_errorCode, status);
		return FALSE;
	}
}


BOOLEAN FLockReadFastFirstMeta(
	__in HANDLE _hFile,
	__out PFLOCK_META _readMetaInfo,
	__out_opt NTSTATUS* _errorCode
	)
{
	BOOLEAN result = FALSE;
	NTSTATUS status = STATUS_NOT_FOUND;
	UCHAR flockMetaSignatureBuffer[16] = FLOCK_META_SIGNATURE;

	const DWORD eaSize = sizeof(FILE_FULL_EA_INFORMATION) + FLOCK_META_NAME_SIZE + sizeof(FLOCK_META);
	UCHAR metaBuffer[sizeof(FILE_FULL_EA_INFORMATION) + FLOCK_META_NAME_SIZE + sizeof(FLOCK_META)] = { 0 };
	PFILE_FULL_EA_INFORMATION pEa = (PFILE_FULL_EA_INFORMATION)metaBuffer;

	//
	// Prepare FILE_GET_EA_INFORMATION structure for future searching.
	//

	CONST DWORD srchEaSize = sizeof(FILE_GET_EA_INFORMATION) + FLOCK_META_NAME_SIZE;
	UCHAR srchEAsBuffer[sizeof(FILE_GET_EA_INFORMATION) + FLOCK_META_NAME_SIZE] = { 0 };
	PFILE_GET_EA_INFORMATION pGetEaInfo = (PFILE_GET_EA_INFORMATION)srchEAsBuffer;

	pGetEaInfo->NextEntryOffset = 0;
	pGetEaInfo->EaNameLength = FLOCK_META_NAME_SIZE;
	memcpy(pGetEaInfo->EaName, FLOCK_META_NAME, FLOCK_META_NAME_SIZE);

	if (_readMetaInfo == NULL){
		SETPTR(_errorCode, STATUS_INVALID_ADDRESS);
		return FALSE;
	}

	//
	// Read only first 'FLOCK_META' attribute.
	//

	IO_STATUS_BLOCK ioStatus;
	status = ZwQueryEaFile(_hFile, &ioStatus, metaBuffer, sizeof(metaBuffer), TRUE, pGetEaInfo, srchEaSize, NULL, TRUE);

	if (status == STATUS_EAS_NOT_SUPPORTED)
	{
		SETPTR(_errorCode, status);

		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: failed - EAs not supported on the file system, status code is 0x%x\n", __FUNCTION__, status));
	}
	else if (status == STATUS_INSUFFICIENT_RESOURCES) // It's not going to happen, but who knows.
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: failed - need more memory (current size is %d), status code is 0x%x\n", __FUNCTION__, srchEaSize, status));

		SETPTR(_errorCode, status);
	}
	else if (status == STATUS_NO_EAS_ON_FILE)
	{
		SETPTR(_errorCode, status);

		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: failed - the file has no EAs, status code is 0x%x\n", __FUNCTION__, status));
	}
	else if (NT_SUCCESS(status))
	{
		//
		// Find FLock meta-information.
		//

		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: Ready to find - FLock EAs\n", __FUNCTION__));

		// 
		// 	This structure is longword - aligned.If a set of FILE_FULL_EA_INFORMATION entries is buffered,
		// 	NextEntryOffset value in each entry, except the last, falls on a longword boundary.
		// 
		// 	The value(s) associated with each entry follows the EaName array.That is, an EA's values are located at EaName + (EaNameLength + 1).
		//

#ifdef _DEBUG
		if (pEa->EaNameLength != 0){
			PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: Found an EA : %s\n", __FUNCTION__, pEa->EaName));
		}
#endif

		//
		// Perform some additional checks.
		//

		if (pEa->EaNameLength == FLOCK_META_NAME_SIZE && (pEa->EaValueLength >= sizeof(FLOCK_META)))
		{
			PCHAR eaName = pEa->EaName;
			PVOID eaValue = pEa->EaName + (pEa->EaNameLength + 1);

			//
			// May be it's better to use RtlCompareUnicodeString(..), because when I store EA with 
			// a lower-case string as a name and when I read it again it's become a UPPER-CASE string.
			// That's why "FLOCK_META" is a UPPER-CASE string.
			//

			BOOLEAN metaFound = memcmp(eaName, FLOCK_META_NAME, FLOCK_META_NAME_SIZE) == 0;

			if (metaFound == TRUE)
			{
				PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: success - FLock meta found.\n", __FUNCTION__));

				PFLOCK_META metaInformation = (PFLOCK_META)eaValue;

				//
				// Second validation it's a verification of the hard-coded meta-information signature.
				//

				if (memcmp(metaInformation->signature, flockMetaSignatureBuffer, sizeof(flockMetaSignatureBuffer)) == 0)
				{
					//
					// Success. All validations are passed. It's ok to return just read EAs.
					//

					PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: success - FLock meta read and validated.\n", __FUNCTION__));

					SETPTR(_errorCode, STATUS_SUCCESS);

					result = TRUE;
				}
				else
				{
					PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: failed - bad FLock meta-signature\n", __FUNCTION__));

					SETPTR(_errorCode, STATUS_BAD_DATA);
				}
			}
			else
			{
				PT_DBG_PRINT(PTDBG_TRACE_ROUTINES | PTDBG_TRACE_ERRORS, ("FLock!%s: error - just read FLock meta has invalid name attribute.\n", __FUNCTION__));

				SETPTR(_errorCode, STATUS_BAD_DATA);
			}
		}
		else
		{
// 			PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: error - just read FLock meta is incorrect. name is %d bytes, value is %d bytes.\n",
// 				__FUNCTION__,
// 				pEa->EaNameLength,
// 				pEa->EaValueLength));

			SETPTR(_errorCode, STATUS_BAD_DATA);
		}
	}
	else
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES | PTDBG_TRACE_ERRORS, ("FLock!%s: failed - can't get EAs, status code is 0x%x (%d)\n", __FUNCTION__, status, status));

		SETPTR(_errorCode, status);
	}

	return result;
}

BOOLEAN FLockFileReadFastFirstMeta(
	__in WCHAR* _filePath,
	__out PFLOCK_META _readMetaInfo,
	__out_opt NTSTATUS* _errorCode
	)
{
	UNICODE_STRING usFilePath = { 0 };

	if (_filePath == NULL){
		SETPTR(_errorCode, STATUS_INVALID_ADDRESS);
		return FALSE;
	}

	RtlInitUnicodeString(&usFilePath, _filePath);

	return FLockFileReadFastFirstMeta2(&usFilePath, _readMetaInfo, _errorCode);
}

BOOLEAN FLockFileReadFastFirstMeta2(
	__in PUNICODE_STRING _filePath,
	__out PFLOCK_META _readMetaInfo,
	__out_opt NTSTATUS* _errorCode
	)
{
	BOOLEAN result = FALSE;
	HANDLE hFile;
	IO_STATUS_BLOCK ioStatus = { 0 };
	OBJECT_ATTRIBUTES oaFile = { 0 };

	if (_filePath == NULL){
		SETPTR(_errorCode, STATUS_INVALID_ADDRESS);
		return FALSE;
	}

	InitializeObjectAttributes(&oaFile, _filePath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

	NTSTATUS status = ZwCreateFile(&hFile,
		FILE_READ_EA /* | FILE_READ_ATTRIBUTES*/,
		&oaFile,
		&ioStatus,
		NULL, // AllocationSize
		FILE_ATTRIBUTE_NORMAL, // FileAttributes
		0, // Exclusive share access
		FILE_OPEN,
		0, //FILE_DIRECTORY_FILE for directory
		NULL, //EaBuffer
		0); // EaLength

	if (NT_SUCCESS(status))
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: Success - %wZ was opened, status code is 0x%x\n", __FUNCTION__, _filePath, status));

		result = FLockReadFastFirstMeta(hFile, _readMetaInfo, &status);
		ZwClose(hFile);
	}
	else
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES | PTDBG_TRACE_ERRORS, ("FLock!%s: failed - can't open file %wZ, status code is 0x%x\n", __FUNCTION__, _filePath, status));
		SETPTR(_errorCode, status);
	}

	return result;
}


BOOLEAN FLockWriteMeta(HANDLE _hFile, PFLOCK_META _metaInfo, NTSTATUS* _errorCode)
{
	BOOLEAN result = FALSE;
	NTSTATUS status;
	IO_STATUS_BLOCK ioStatus = { 0 };
	//const DWORD eaSize = sizeof(FILE_FULL_EA_INFORMATION) + FLOCK_META_NAME_SIZE + sizeof(FLOCK_META);
	UCHAR metaBuffer[ sizeof(FILE_FULL_EA_INFORMATION) + FLOCK_META_NAME_SIZE + sizeof(FLOCK_META) ] = { 0 };

	if (_metaInfo == NULL) {
		SETPTR(_errorCode, STATUS_INVALID_ADDRESS);
		return FALSE;
	}

	PFILE_FULL_EA_INFORMATION pEaInfo = (PFILE_FULL_EA_INFORMATION)metaBuffer;
	pEaInfo->Flags = 0;
	pEaInfo->NextEntryOffset = 0; // We have only one entry.
	pEaInfo->EaNameLength = FLOCK_META_NAME_SIZE;
	pEaInfo->EaValueLength = sizeof(FLOCK_META);

	PUCHAR pEaName = (PUCHAR)pEaInfo->EaName;
	PUCHAR pEaValue = pEaName + FLOCK_META_NAME_SIZE + 1 /* last zero symbol */;

	memcpy(pEaName, FLOCK_META_NAME, FLOCK_META_NAME_SIZE);
	memcpy(pEaValue, _metaInfo, sizeof(FLOCK_META));

	status = ZwSetEaFile(_hFile, &ioStatus, metaBuffer, sizeof(metaBuffer));

	if (NT_SUCCESS(status))
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: Success - FLock meta data was written as EAs\n", __FUNCTION__));

		result = TRUE;
	}
	else
	{
		SETPTR(_errorCode, status);

		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: failed - can't write FLock meta, status code is 0x%x (%d)\n", __FUNCTION__, status, status));
	}

	return result;
}

BOOLEAN FLockHasMeta(HANDLE _hFile)
{
	FLOCK_META fm = { 0 };
	NTSTATUS status;

	return FLockReadFastFirstMeta(_hFile, &fm, &status) == TRUE;
}

VOID FLockGetFLockMetaName(
	__out PUNICODE_STRING _result
	)
{

}

BOOLEAN FLockFileWriteMeta(
	__in WCHAR* _filePath,
	__in PFLOCK_META _metaInfo,
	__out_opt NTSTATUS* _errorCode
	)
{
	BOOLEAN result = FALSE;
	HANDLE hFile;
	IO_STATUS_BLOCK ioStatus = { 0 };
	OBJECT_ATTRIBUTES oaFile = { 0 };
	UNICODE_STRING usFilePath = { 0 };

	if (_filePath == NULL){
		SETPTR(_errorCode, STATUS_INVALID_ADDRESS);
		return FALSE;
	}

	RtlInitUnicodeString(&usFilePath, _filePath);

	InitializeObjectAttributes(&oaFile, &usFilePath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

	NTSTATUS status = ZwCreateFile(&hFile,
		FILE_WRITE_EA /* | FILE_WRITE_ATTRIBUTES*/,
		&oaFile,
		&ioStatus,
		NULL, // AllocationSize
		FILE_ATTRIBUTE_NORMAL, // FileAttributes
		0, // Exclusive share access
		FILE_OPEN,
		0, // FILE_DIRECTORY_FILE for directory
		NULL, //EaBuffer
		0); // EaLength

	if (NT_SUCCESS(status))
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: Success - file was open %wZ\n", __FUNCTION__, &usFilePath));

		result = FLockWriteMeta(hFile, _metaInfo, _errorCode);

		if (result == TRUE)
		{
			PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: Success - FLock meta was written to %wZ\n", __FUNCTION__, &usFilePath));
		} else {
			PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: failed - can't write FLock meta to %wZ, status code is 0x%x\n", __FUNCTION__, &usFilePath, status));
		}

		ZwClose(hFile);
	}
	else
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: failed - can't open file %wZ, status code is 0x%x\n", __FUNCTION__, &usFilePath, status));

		SETPTR(_errorCode, status);
	}

	return result;
}


BOOLEAN FLockFileWriteMeta2(
	__in PUNICODE_STRING _filePath,
	__in PFLOCK_META _metaInfo,
	__out_opt NTSTATUS* _errorCode
	)
{
	BOOLEAN result = FALSE;
	HANDLE hFile;
	IO_STATUS_BLOCK ioStatus = { 0 };
	OBJECT_ATTRIBUTES oaFile = { 0 };

	if ( (_filePath == NULL) || (_metaInfo == NULL) ){
		SETPTR(_errorCode, STATUS_INVALID_ADDRESS);
		return FALSE;
	}

	InitializeObjectAttributes(&oaFile, _filePath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

	NTSTATUS status = ZwCreateFile(&hFile,
		FILE_WRITE_EA /* | FILE_WRITE_ATTRIBUTES*/,
		&oaFile,
		&ioStatus,
		NULL, // AllocationSize
		FILE_ATTRIBUTE_NORMAL, // FileAttributes
		0, // Exclusive share access
		FILE_OPEN,
		0, // FILE_DIRECTORY_FILE for directory
		NULL, //EaBuffer
		0); // EaLength

	if (NT_SUCCESS(status))
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: Success - file was open %wZ\n", __FUNCTION__, _filePath));

		result = FLockWriteMeta(hFile, _metaInfo, _errorCode);

		if (result == TRUE)
		{
			PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: Success - FLock meta was written to %wZ\n", __FUNCTION__, _filePath));
		} else {
			PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: failed - can't write FLock meta to %wZ, status code is 0x%x\n", __FUNCTION__, _filePath, status));
		}

		ZwClose(hFile);
	}
	else
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: failed - can't open file %wZ, status code is 0x%x\n", __FUNCTION__, _filePath, status));

		SETPTR(_errorCode, status);
	}

	return result;
}


BOOLEAN FLockHasBackslash(
	__in PUNICODE_STRING _str
	)
{
	if (_str->Length)
	{
		if (_str->Buffer[WCHAR_COUNT(_str->Length) - 1] == L'\\')
		{
			return TRUE;
		}
	}

	return FALSE;
}


BOOLEAN FLockEqualAnsiStrings(
	__in PANSI_STRING _first,
	__in PANSI_STRING _second
	)
{
	if (_first && _second)
	{
		if ((_first->Length != 0) && (_first->Length == _second->Length))
		{
			for (USHORT i = 0; i < _first->Length; i++){
				if (_first->Buffer[i] != _second->Buffer[i]){
					return FALSE;
				}
			}

			return TRUE;
		}

	}

	return FALSE;
}