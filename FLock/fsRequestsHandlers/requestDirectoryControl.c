//
// Author:
//		Burlutsky Stas
//
//		burluckij@gmail.com
//

#include "../flock.h"
#include "../FLockStorage.h"

#define FLOCK_FIELD_READ(_base, _offset, _fieldType)				(   *( (_fieldType*)( ((PUCHAR)_base) + _offset) )   )
#define FLOCK_FIELD_PTR(_base, _offset, _fieldType)					(   ( (_fieldType*)( ((PUCHAR)_base) + _offset) )   )

#define FLOCK_WRITE_FIELD(_base, _offset, _fieldType, _value)		(   *((_fieldType*)(((PUCHAR)_base) + _offset)) = _value  )



extern ULONG gTraceFlags;
extern FLOCK_DEVICE_DATA g_flockData;




NTSTATUS
FLockHandleFileBothDirectoryInformation(
_Inout_ PFLT_CALLBACK_DATA Data,
_In_ PCFLT_RELATED_OBJECTS FltObjects,
__in PUNICODE_STRING _requestedDir
);


NTSTATUS
FLockHandleFileDirectoryInformation(
_Inout_ PFLT_CALLBACK_DATA Data,
_In_ PCFLT_RELATED_OBJECTS FltObjects,
__in PUNICODE_STRING _requestedDir
);


NTSTATUS
FLockHandleFileFullDirectoryInformation(
_Inout_ PFLT_CALLBACK_DATA Data,
_In_ PCFLT_RELATED_OBJECTS FltObjects,
__in PUNICODE_STRING _requestedDir
);


NTSTATUS
FLockHandleFileIdBothDirectoryInformation(
_Inout_ PFLT_CALLBACK_DATA Data,
_In_ PCFLT_RELATED_OBJECTS FltObjects,
__in PUNICODE_STRING _requestedDir
);


NTSTATUS
FLockHandleFileIdFullDirectoryInformation(
_Inout_ PFLT_CALLBACK_DATA Data,
_In_ PCFLT_RELATED_OBJECTS FltObjects,
__in PUNICODE_STRING _requestedDir
);


NTSTATUS
FLockHandleFileNamesInformation(
_Inout_ PFLT_CALLBACK_DATA Data,
_In_ PCFLT_RELATED_OBJECTS FltObjects,
__in PUNICODE_STRING _requestedDir
);


NTSTATUS
FLockHandleFileObjectIdInformation(
_Inout_ PFLT_CALLBACK_DATA Data,
_In_ PCFLT_RELATED_OBJECTS FltObjects,
__in PUNICODE_STRING _requestedDir
);


NTSTATUS
FLockHandleFileReparsePointInformation(
_Inout_ PFLT_CALLBACK_DATA Data,
_In_ PCFLT_RELATED_OBJECTS FltObjects,
__in PUNICODE_STRING _requestedDir
);


NTSTATUS
FLockHandleByPath(
_Inout_ PFLT_CALLBACK_DATA Data,
__in PUNICODE_STRING _requestedDir,
__in ULONG _offsetNextEntry,
__in ULONG _offsetFileNameLength,
__in ULONG _offsetFileName
);


FLT_PREOP_CALLBACK_STATUS FLockPreDirectoryControl(
	_Inout_ PFLT_CALLBACK_DATA    Data,
	_In_    PCFLT_RELATED_OBJECTS FltObjects,
	_Out_   PVOID                 *CompletionContext
	)
{
	UNREFERENCED_PARAMETER(CompletionContext);
	UNREFERENCED_PARAMETER(Data);
	UNREFERENCED_PARAMETER(FltObjects);

	NTSTATUS status;
	BOOLEAN result;

	if (FLT_IS_FASTIO_OPERATION(Data))
	{
		return FLT_PREOP_DISALLOW_FASTIO;
	}

	if (BooleanFlagOn(Data->Iopb->OperationFlags, SL_OPEN_PAGING_FILE))
	{
		//PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: warning - its a page file opening.", __FUNCTION__));
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	if (BooleanFlagOn(FltObjects->FileObject->Flags, FO_VOLUME_OPEN))
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: info - this is a volume open operation.", __FUNCTION__));
	}

// #ifndef _DEBUG
// 	if (!FLockStorageHasHiddenUserObjects())
// 	{
// 		//
// 		// There is no one object which should be hidden.
// 		//
// 		return FLT_PREOP_SUCCESS_NO_CALLBACK;
// 	}
// #endif

// 	if (IoGetTopLevelIrp() == FSRTL_FSP_TOP_LEVEL_IRP)
// 	{
// 		return FLT_PREOP_SUCCESS_NO_CALLBACK;
// 	}

	if (Data->Iopb->TargetFileObject){
		if (FsRtlIsPagingFile(Data->Iopb->TargetFileObject)){
			PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: it is page file opening. Ignore.\n", __FUNCTION__));
			return FLT_PREOP_SUCCESS_NO_CALLBACK;
		}
	}
	else
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: warning it's no FILE_OBJECT.\n", __FUNCTION__));
	}

	if (!FLT_IS_IRP_OPERATION(Data))
	{
		//PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: it is not IRP based operation.\n", __FUNCTION__));
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	if (Data->Iopb->MinorFunction != IRP_MN_QUERY_DIRECTORY)
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: ignore request which is not (IRP_MN_QUERY_DIRECTORY), MinorFunction is 0x%x.\n", __FUNCTION__, Data->Iopb->MinorFunction));
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	//
	// Path is c:\work\dir
	// Нужно ли нам скрывать что-то для этого каталога? 
	// Он может быть родительским для целевого, скрываемого нами каталога - c:\work\dir\hidden
	//

	FLOCK_META fm = { 0 };
	UNICODE_STRING filepath = { 0 };

	if (Data->Iopb->TargetFileObject)
	{
		//
		// Read flock-meta skipping opening file operation using earlier created FILE_OBJECT.
		//

		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: call for Data->Iopb->TargetFileObject.\n", __FUNCTION__));

		result = FLockFltReadFirstMeta(Data->Iopb->TargetInstance, Data->Iopb->TargetFileObject, &fm, &status);
	}
	else
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: open and read info.\n", __FUNCTION__));

		result = FLockFltReadFirstMetaWithGetFilePath(
			g_flockData.filterHandle,
			Data->Iopb->TargetInstance,
			Data,
			&fm,
			&filepath,
			&status);
	}

	if (result)
	{
		FLockPrintMeta(&fm);

		//
		// There is something to protect.
		//

		if (fm.flags & FLOCK_FLAG_HAS_FLOCKS)
		{
			if (filepath.Length)
			{
				PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: there is something to protect in %wZ\n", __FUNCTION__, &filepath));

				ExFreePool(filepath.Buffer);
			}
			else
			{
				PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: there is something to protect in the directory.\n", __FUNCTION__));
			}

			//
			// Hide target objects in post-callback.
			//

			return FLT_PREOP_SYNCHRONIZE;
		}
	}
	else
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: error - can't read flock-meta, status is 0x%x\n", __FUNCTION__, status));
	}

	//
	// There is nothing to hide in requested directory.
	//

	return FLT_PREOP_SUCCESS_NO_CALLBACK;
}


FLT_POSTOP_CALLBACK_STATUS FLockPostDirectoryControl(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_opt_ PVOID CompletionContext,
	_In_ FLT_POST_OPERATION_FLAGS Flags
	)
{
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(CompletionContext);
	UNREFERENCED_PARAMETER(Flags);

	NTSTATUS status = STATUS_UNSUCCESSFUL;

	if (!NT_SUCCESS(Data->IoStatus.Status) || Data->IoStatus.Status == STATUS_REPARSE)
	{
		return FLT_POSTOP_FINISHED_PROCESSING;
	}

	if (IoGetTopLevelIrp() == FSRTL_FSP_TOP_LEVEL_IRP)
	{
		return FLT_POSTOP_FINISHED_PROCESSING;
	}

	if (FsRtlIsPagingFile(Data->Iopb->TargetFileObject))
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s it is page file opening. Ignore.\n", __FUNCTION__));
		return FLT_POSTOP_FINISHED_PROCESSING;
	}

	PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: (IRP_MN_QUERY_DIRECTORY is 0x01), MinorFunction is 0x%x.\n", __FUNCTION__, Data->Iopb->MinorFunction));

	if (Data->Iopb->MinorFunction != IRP_MN_QUERY_DIRECTORY)
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: ignore request which is not (IRP_MN_QUERY_DIRECTORY = 0x01), MinorFunction is 0x%x.\n", __FUNCTION__, Data->Iopb->MinorFunction));
		return FLT_POSTOP_FINISHED_PROCESSING;
	}

	PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: ready to process the request.\n", __FUNCTION__));

	//
	// Lookup flock-meta information.
	//

// 	FLOCK_META fm = { 0 };
// 	BOOLEAN result = FLockFltReadFirstMeta(Data->Iopb->TargetInstance, Data->Iopb->TargetFileObject, &fm, &status);
// 
// 	if (result)
// 	{
// 		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: print just read flock-meta...\n", __FUNCTION__));
// 
// 		FLockPrintMeta(&fm);
// 
// 		//
// 		// There is something to protect.
// 		//
// 
// 		if (fm.flags & FLOCK_FLAG_HAS_FLOCKS)
// 		{
// 			PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: there is something to protect.\n", __FUNCTION__));
// 		}
// 		else
// 		{
// 			PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: there is nothing to protect.\n", __FUNCTION__));
// 
// 			//
// 			// Hide target objects in post-callback.
// 			//
// 
// 			return FLT_POSTOP_FINISHED_PROCESSING;
// 		}
// 	}
// 	else
// 	{
// 		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: not found any flock-meta.\n", __FUNCTION__));
// 
// 		return FLT_POSTOP_FINISHED_PROCESSING;
// 	}

	//
	// Do not read data from VOLUME.
	//
	// ...

	//
	// Read file path and pass it further.
	//
	
	UNICODE_STRING requestedDirPath = { 0 };
	BOOLEAN result = FLockFltGetPath(g_flockData.filterHandle, Data->Iopb->TargetInstance, Data, &requestedDirPath, &status);

	if (!result)
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: error - can't get requested directory path.\n", __FUNCTION__));
		return FLT_POSTOP_FINISHED_PROCESSING;
	}

	FILE_INFORMATION_CLASS infoClass = Data->Iopb->Parameters.DirectoryControl.QueryDirectory.FileInformationClass;
	//ULONG length = Data->Iopb->Parameters.DirectoryControl.QueryDirectory.Length;
	//PUNICODE_STRING pRequestedFileName = Data->Iopb->Parameters.DirectoryControl.QueryDirectory.FileName;
	//PMDL mdlAddress = Data->Iopb->Parameters.DirectoryControl.QueryDirectory.MdlAddress;
	//PVOID buffer = Data->Iopb->Parameters.DirectoryControl.QueryDirectory.DirectoryBuffer;
	
	switch (infoClass)
	{
	case FileBothDirectoryInformation:
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: requested 'FileBothDirectoryInformation'\n", __FUNCTION__));
		status = FLockHandleFileBothDirectoryInformation(Data, FltObjects, &requestedDirPath);
		break;

	case FileDirectoryInformation:
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: requested 'FileDirectoryInformation'\n", __FUNCTION__));
		status = FLockHandleFileDirectoryInformation(Data, FltObjects, &requestedDirPath);
		break;

	case FileFullDirectoryInformation:
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: requested 'FileFullDirectoryInformation'\n", __FUNCTION__));
		status = FLockHandleFileFullDirectoryInformation(Data, FltObjects, &requestedDirPath);
		break;

	case FileIdBothDirectoryInformation:
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: requested 'FileIdBothDirectoryInformation'\n", __FUNCTION__));
		status = FLockHandleFileIdBothDirectoryInformation(Data, FltObjects, &requestedDirPath);
		break;

	case FileIdFullDirectoryInformation:
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: requested 'FileIdFullDirectoryInformation'\n", __FUNCTION__));
		status = FLockHandleFileIdFullDirectoryInformation(Data, FltObjects, &requestedDirPath);
		break;

	case FileNamesInformation:
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: requested 'FileNamesInformation'\n", __FUNCTION__));
		status = FLockHandleFileNamesInformation(Data, FltObjects, &requestedDirPath);
		break;

	case FileObjectIdInformation:
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: requested 'FileObjectIdInformation'\n", __FUNCTION__));
		break;

	case FileReparsePointInformation:
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: requested 'FileReparsePointInformation'\n", __FUNCTION__));
		break;

	default:
		status = STATUS_UNSUCCESSFUL;
		break;
	}

	//
	// Проверить extended attributes и удалить объект из списка, если требуется.
	//

	if (requestedDirPath.Buffer){
		ExFreePool(requestedDirPath.Buffer);
	}

	return FLT_POSTOP_FINISHED_PROCESSING;
}


//
// Routines for hiding objects.
//

NTSTATUS
FLockHandleByPath2(
_Inout_ PFLT_CALLBACK_DATA Data,
__in PUNICODE_STRING _requestedDir,
__in ULONG _offsetNextEntry,
__in ULONG _offsetFileNameLength,
__in ULONG _offsetFileName,
__in ULONG _sizeOfStruct,
__in ULONG _offsetShortFileName // could be or couldn't be - depends from structure.
)
{
	NTSTATUS status = 0;
	FLOCK_META fm = { 0 };

	//
	// That parameter indicates - Does the directory really contain one or more file which required to be hidden?
	// If actually the directory has no one object with FLOCK_META in EAs - it means that we should remove
	// FLOCK_FLAG_HAS_FLOCKS flag from the directory. It helps us to improve system performance and avoid unnecessary filtering actions.
	//
	BOOLEAN flockMetaFound = FALSE;
	BOOLEAN accessDeniedOccurred = FALSE;

	ULONG bufferLength = Data->Iopb->Parameters.DirectoryControl.QueryDirectory.Length;
	PMDL mdlAddress = Data->Iopb->Parameters.DirectoryControl.QueryDirectory.MdlAddress;
	PVOID buffer = Data->Iopb->Parameters.DirectoryControl.QueryDirectory.DirectoryBuffer;
	UNICODE_STRING filePathString = { 0 };
	USHORT allocatedBufferLength = _requestedDir->Length + WCHAR_LEN(512);

	WCHAR* preAllocatedFullFilePath = ExAllocatePool(NonPagedPool, allocatedBufferLength);
	if (!preAllocatedFullFilePath)
	{
		//
		// Ignore handling in case we have no memory.
		//

		return STATUS_INSUFFICIENT_RESOURCES;
	}

	RtlInitEmptyUnicodeString(&filePathString, preAllocatedFullFilePath, allocatedBufferLength);
	RtlCopyUnicodeString(&filePathString, _requestedDir);

	if ((buffer == NULL) && (mdlAddress != NULL))
	{
		// Work with an MDL?
	}

	if (buffer)
	{
		for (PUCHAR pFileInfo = (PUCHAR)buffer, prev = NULL;;)
		{
			ULONG nextEntryOffset = FLOCK_FIELD_READ(pFileInfo, _offsetNextEntry, ULONG);
			ULONG fileNameLength = FLOCK_FIELD_READ(pFileInfo, _offsetFileNameLength, ULONG);
			BOOLEAN result = FALSE, requireHide = FALSE;

			//
			// In each directory we have as minimum two sub folders '.',  '..'
			// but not in the root (volume) directory - "c:\","x:\".
			//

			//
			// Save pointer on first unreferenced object.
			//
			if (prev == NULL){
				prev = pFileInfo;
			}


			ULONG requieredSize = _requestedDir->Length + 2 * sizeof(WCHAR) /* for the back slash symbol '\' */ + fileNameLength /* pFileInfo->FileNameLength */;
			if (requieredSize > allocatedBufferLength)
			{
				//
				// Free memory for the old buffer and allocate new memory block.
				//
				ExFreePool(preAllocatedFullFilePath);

				preAllocatedFullFilePath = ExAllocatePool(NonPagedPool, requieredSize);
				if (!preAllocatedFullFilePath)
				{
					//
					// That is not good to as we do.
					//
					return STATUS_INSUFFICIENT_RESOURCES;
				}

				//
				// Save new buffer size and prepare unicode string for future work.
				//

				allocatedBufferLength = (USHORT)requieredSize;

				RtlInitEmptyUnicodeString(&filePathString, preAllocatedFullFilePath, allocatedBufferLength);
				RtlCopyUnicodeString(&filePathString, _requestedDir);
			}

			//
			// Cut a length of the string.
			//

			filePathString.Length = _requestedDir->Length;

			UNICODE_STRING fileName;
			fileName.Length = (USHORT)fileNameLength /*pFileInfo->FileNameLength*/;
			fileName.MaximumLength = (USHORT)fileNameLength; // pFileInfo->FileNameLength;
			fileName.Buffer = FLOCK_FIELD_PTR(pFileInfo, _offsetFileName, WCHAR); //pFileInfo->FileName;

			//
			// Add backslash if it's need. Ignore all NT_SUCCESS validations, the memory was prepared earlier.
			//
			if (!FLockHasBackslash(&filePathString)) {
				RtlAppendUnicodeToString(&filePathString, L"\\");
			}

			RtlAppendUnicodeStringToString(&filePathString, &fileName);

			//
			// Print name of the just built file path.
			//

			PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: file enumerate: %wZ, full path is %wZ\n", __FUNCTION__, &fileName, &filePathString));

			//
			// Open the file by path.
			//

			result = FLockFltOpenAndReadFirstMeta(g_flockData.filterHandle, Data->Iopb->TargetInstance, &filePathString, &fm, &status);
			if (result)
			{
				// Yes, that directory really has something to protect.
				flockMetaFound = TRUE;

				requireHide = (fm.flags & FLOCK_FLAG_HIDE);
				if (requireHide)
				{
					PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: to hide the file - %wZ\n", __FUNCTION__, &filePathString));
				}
			}
			else
			{
				if (status == STATUS_ACCESS_DENIED)
				{
					accessDeniedOccurred = TRUE;
					PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: error - can't touch %wZ (status is 0x%x)\n", __FUNCTION__, &filePathString, status));
				}
			}

			//
			// Process the file, hide it if it's really need.
			//

			if (requireHide)
			{
				PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: require to hide: %wZ\n", __FUNCTION__, &filePathString));

				if (prev == pFileInfo)
				{
					//
					// In sub folder we two included directories - "." and "..", but we have no them
					// when we are in the root of volume - "\Device\HarddiskVolume1\".
					//
					// Here we have to handle following cases:
					//
					//	1. There is only one file\folder in the root and in that case we can some things:
					//		* Complete the request with an error;
					//		* Show file with unknown name.
					//
					//	2. There are many different files but our file (or files!) is first in the list.
					//		* Move all entries to top position (from end to begin).
					//

					PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: there is no previous entry for : %wZ\n", __FUNCTION__, &filePathString));

					if (nextEntryOffset)
					{
						//
						// There are some entries after current, move them all from end to begin of the buffer.
						//

						PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: there is a next entry for : %wZ\n", __FUNCTION__, &filePathString));

						PUCHAR nextEntryAddress = (PUCHAR)pFileInfo + nextEntryOffset;
						ULONG sizeOfDataToMove = ((PUCHAR)buffer + bufferLength) /* end of buffer */ - ((PUCHAR) nextEntryAddress) /* next entry */;

						RtlCopyMemory(pFileInfo, nextEntryAddress, sizeOfDataToMove);

						FltIsCallbackDataDirty(Data);

						// Go to next iteration.
						prev = NULL;
						continue;
					}
					else
					{
						//
						// This is a single entry which should be protected. There no others - before and after us.
						//

						PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: ignore. There is no next entry for : %wZ\n", __FUNCTION__, &filePathString));
						
						//
						// Change name to the file. It happens seldom but we can handle and that case too.
						//

						WCHAR replaceSymbol = L'R';
						PWCHAR fileNameBuffer = FLOCK_FIELD_PTR(pFileInfo, _offsetFileName, WCHAR); //pFileInfo->FileName;

						for (ULONG pos = 0; pos < fileNameLength; pos++){
							fileNameBuffer[pos] = replaceSymbol;
						}

						if (_offsetShortFileName != 0){
							PWCHAR shortFileNameBuffer = FLOCK_FIELD_PTR(pFileInfo, _offsetShortFileName, WCHAR); //pFileInfo->ShortName;
							ULONG shortNameBufferSize = 12 /* WCHARs */; 
							for (ULONG pos = 0; pos < shortNameBufferSize; pos++){
								WCHAR ch = shortFileNameBuffer[pos];
								if ((ch != 0) && (ch != L'.')){
									shortFileNameBuffer[pos] = replaceSymbol;
								}
							}
						}
					}
				}
				else
				{
					if (nextEntryOffset) /*pFileInfo->NextEntryOffset*/
					{
						//
						// Calculate offset to next element for previous entry.
						// That next element actually is an element which is the next for current (hiding) element. 
						//

						ULONG offset = ((ULONG)((PUCHAR)pFileInfo - (PUCHAR)prev)) + nextEntryOffset;
						//offset = ALIGN_DOWN(offset, LONGLONG);

						FLOCK_WRITE_FIELD(prev, _offsetNextEntry, ULONG, offset);
						// prev->NextEntryOffset = offset;

						RtlZeroMemory(pFileInfo, _sizeOfStruct);

						PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: set prev->NextEntryOffset to %d for - %wZ\n", __FUNCTION__, offset, &filePathString));
					}
					else
					{
						//
						// We have previous entry, but have no next.
						// Mark previous as last and write zeros for our (hiding) entry.
						//
						FLOCK_WRITE_FIELD(prev, _offsetNextEntry, ULONG, 0);
						//prev->NextEntryOffset = 0;

						// Here I do not delete fileName (only first character). I remove just a part of the structure with fixed size.
						RtlZeroMemory(pFileInfo, _sizeOfStruct);

						PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: mark previous entry as last - %wZ\n", __FUNCTION__));
					}

					//
					// I'm not sure about that call, but it's better to do than not! 
					// Because actually we just changed the original data.
					//

					FltIsCallbackDataDirty(Data);
				}
			}
			else
			{
				//
				// Update link.
				//

				prev = pFileInfo;
			}

			//
			// To go further if it's where to go =)
			//

			//ULONG nextEntry = FLOCK_FIELD_READ(pFileInfo, _offsetNextEntry, ULONG);
			if (nextEntryOffset /*pFileInfo->NextEntryOffset*/)
			{
				pFileInfo = ((PUCHAR)pFileInfo + nextEntryOffset);
			} else {
				break;
			}
		}
	}

	//
	// Do some optimization things.
	//
	if ((!flockMetaFound) && (!accessDeniedOccurred))
	{
		//
		// Here can decide to remove FLOCK_META from requested directory because 
		// actually we did not find any included FLOCK_META in no one included file
		// and also we did not get access denied error while read extended attributes.
		//

		FLOCK_META targetDirFm = { 0 };
		if (FLockFltReadFirstMeta(Data->Iopb->TargetInstance, Data->Iopb->TargetFileObject, &targetDirFm, &status))
		{
			ClearFlag(targetDirFm.flags, FLOCK_FLAG_HAS_FLOCKS);

			if (FLockFltWriteFlockMeta(Data->Iopb->TargetInstance, Data->Iopb->TargetFileObject, &targetDirFm, &status))
			{
				PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: success - unused flag was cleared in flock's meta\n", __FUNCTION__));
			} else {
				PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: error - couldn't clear flag of flock meta info in target directory, status is 0x%x\n", __FUNCTION__, status));
			}
		}
	}


	if (preAllocatedFullFilePath){
		ExFreePool(preAllocatedFullFilePath);
	}

	return STATUS_SUCCESS;
}


//
// All functions placed below - does the same like FLockHandleFileIdBothDirectoryInformation(..)
//

//
// I'll change all that code to something common and will move it somewhere.
//

NTSTATUS
FLockHandleFileIdBothDirectoryInformation(
_Inout_ PFLT_CALLBACK_DATA Data,
_In_ PCFLT_RELATED_OBJECTS FltObjects,
__in PUNICODE_STRING _requestedDir
)
{
	UNREFERENCED_PARAMETER(FltObjects);

	const ULONG offsetNextEntry = OFFSET_OF(FILE_ID_BOTH_DIR_INFORMATION, NextEntryOffset);
	const ULONG offsetFileNameLength = OFFSET_OF(FILE_ID_BOTH_DIR_INFORMATION, FileNameLength);
	const ULONG offsetFileName = OFFSET_OF(FILE_ID_BOTH_DIR_INFORMATION, FileName);
	const ULONG sizeOfStructure = sizeof(FILE_ID_BOTH_DIR_INFORMATION);
	const ULONG offsetShortName = OFFSET_OF(FILE_ID_BOTH_DIR_INFORMATION, ShortName);

	return FLockHandleByPath2(Data, _requestedDir, offsetNextEntry, offsetFileNameLength, offsetFileName, sizeOfStructure, offsetShortName);
}

NTSTATUS
FLockHandleFileBothDirectoryInformation(
_Inout_ PFLT_CALLBACK_DATA Data,
_In_ PCFLT_RELATED_OBJECTS FltObjects,
__in PUNICODE_STRING _requestedDir
)
{
	UNREFERENCED_PARAMETER(FltObjects);

	const ULONG offsetNextEntry = OFFSET_OF(FILE_BOTH_DIR_INFORMATION, NextEntryOffset);
	const ULONG offsetFileNameLength = OFFSET_OF(FILE_BOTH_DIR_INFORMATION, FileNameLength);
	const ULONG offsetFileName = OFFSET_OF(FILE_BOTH_DIR_INFORMATION, FileName);
	const ULONG sizeOfStructure = sizeof(FILE_BOTH_DIR_INFORMATION);
	const ULONG offsetShortName = OFFSET_OF(FILE_BOTH_DIR_INFORMATION, ShortName);

	return FLockHandleByPath2(Data, _requestedDir, offsetNextEntry, offsetFileNameLength, offsetFileName, sizeOfStructure, offsetShortName);
}


NTSTATUS
FLockHandleFileDirectoryInformation(
_Inout_ PFLT_CALLBACK_DATA Data,
_In_ PCFLT_RELATED_OBJECTS FltObjects,
__in PUNICODE_STRING _requestedDir
)
{
	UNREFERENCED_PARAMETER(FltObjects);

	const ULONG offsetNextEntry = OFFSET_OF(FILE_DIRECTORY_INFORMATION, NextEntryOffset);
	const ULONG offsetFileNameLength = OFFSET_OF(FILE_DIRECTORY_INFORMATION, FileNameLength);
	const ULONG offsetFileName = OFFSET_OF(FILE_DIRECTORY_INFORMATION, FileName);
	const ULONG sizeOfStructure = sizeof(FILE_DIRECTORY_INFORMATION);

	return FLockHandleByPath2(Data, _requestedDir, offsetNextEntry, offsetFileNameLength, offsetFileName, sizeOfStructure, 0);
}


NTSTATUS
FLockHandleFileFullDirectoryInformation(
_Inout_ PFLT_CALLBACK_DATA Data,
_In_ PCFLT_RELATED_OBJECTS FltObjects,
__in PUNICODE_STRING _requestedDir
)
{
	UNREFERENCED_PARAMETER(FltObjects);

	const ULONG offsetNextEntry = OFFSET_OF(FILE_FULL_DIR_INFORMATION, NextEntryOffset);
	const ULONG offsetFileNameLength = OFFSET_OF(FILE_FULL_DIR_INFORMATION, FileNameLength);
	const ULONG offsetFileName = OFFSET_OF(FILE_FULL_DIR_INFORMATION, FileName);
	const ULONG sizeOfStructure = sizeof(FILE_FULL_DIR_INFORMATION);

	return FLockHandleByPath2(Data, _requestedDir, offsetNextEntry, offsetFileNameLength, offsetFileName, sizeOfStructure, 0);
}


NTSTATUS
FLockHandleFileIdFullDirectoryInformation(
_Inout_ PFLT_CALLBACK_DATA Data,
_In_ PCFLT_RELATED_OBJECTS FltObjects,
__in PUNICODE_STRING _requestedDir
)
{
	UNREFERENCED_PARAMETER(FltObjects);

	const ULONG offsetNextEntry = OFFSET_OF(FILE_ID_FULL_DIR_INFORMATION, NextEntryOffset);
	const ULONG offsetFileNameLength = OFFSET_OF(FILE_ID_FULL_DIR_INFORMATION, FileNameLength);
	const ULONG offsetFileName = OFFSET_OF(FILE_ID_FULL_DIR_INFORMATION, FileName);
	const ULONG sizeOfStructure = sizeof(FILE_ID_FULL_DIR_INFORMATION);

	return FLockHandleByPath2(Data, _requestedDir, offsetNextEntry, offsetFileNameLength, offsetFileName, sizeOfStructure, 0);
}


NTSTATUS
FLockHandleFileNamesInformation(
_Inout_ PFLT_CALLBACK_DATA Data,
_In_ PCFLT_RELATED_OBJECTS FltObjects,
__in PUNICODE_STRING _requestedDir
)
{
	UNREFERENCED_PARAMETER(FltObjects);

	const ULONG offsetNextEntry = OFFSET_OF(FILE_NAMES_INFORMATION, NextEntryOffset);
	const ULONG offsetFileNameLength = OFFSET_OF(FILE_NAMES_INFORMATION, FileNameLength);
	const ULONG offsetFileName = OFFSET_OF(FILE_NAMES_INFORMATION, FileName);
	const ULONG sizeOfStructure = sizeof(FILE_NAMES_INFORMATION);

	return FLockHandleByPath2(Data, _requestedDir, offsetNextEntry, offsetFileNameLength, offsetFileName, sizeOfStructure, 0);
}

NTSTATUS
FLockHandleFileObjectIdInformation(
_Inout_ PFLT_CALLBACK_DATA Data,
_In_ PCFLT_RELATED_OBJECTS FltObjects,
__in PUNICODE_STRING _requestedDir
)
{
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(Data);
	UNREFERENCED_PARAMETER(_requestedDir);

	return STATUS_NOT_IMPLEMENTED;
}


NTSTATUS
FLockHandleFileReparsePointInformation(
_Inout_ PFLT_CALLBACK_DATA Data,
_In_ PCFLT_RELATED_OBJECTS FltObjects,
__in PUNICODE_STRING _requestedDir
)
{
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(Data);
	UNREFERENCED_PARAMETER(_requestedDir);

	return STATUS_NOT_IMPLEMENTED;
}
