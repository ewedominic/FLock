//
// Author:
//		Burlutsky Stas
//
//		burluckij@gmail.com
//

#include "../flock.h"


extern ULONG gTraceFlags;


FLT_PREOP_CALLBACK_STATUS FLockPreSetEa(
	_Inout_ PFLT_CALLBACK_DATA    Data,
	_In_    PCFLT_RELATED_OBJECTS FltObjects,
	_Out_   PVOID                 *CompletionContext
	)
{
	UNREFERENCED_PARAMETER(CompletionContext);
	UNREFERENCED_PARAMETER(FltObjects);

	NTSTATUS status = STATUS_UNSUCCESSFUL;

	if (FLT_IS_FASTIO_OPERATION(Data))
	{
		return FLT_PREOP_DISALLOW_FASTIO;
	}

	if (!FLT_IS_IRP_OPERATION(Data))
	{
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	if (BooleanFlagOn(Data->Iopb->OperationFlags, SL_OPEN_PAGING_FILE))
	{
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

// 	if (IoGetTopLevelIrp() == FSRTL_FSP_TOP_LEVEL_IRP)
// 	{
// 		return FLT_PREOP_SUCCESS_NO_CALLBACK;
// 	}

	if (Data->Iopb->TargetFileObject){
		if (FsRtlIsPagingFile(Data->Iopb->TargetFileObject)){
			return FLT_PREOP_SUCCESS_NO_CALLBACK;
		}
	}

	//
	// Do not handle that request if we are in context of service process.
	// Service process can do whatever it wants.
	//
	if (FLockAreWeInServiceProcessContext())
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: info - this is a service process context, do not process it.\n", __FUNCTION__));
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	//
	// If nobody can write flock-meta in EAs of file, we can verify a list of setting attributes
	// and do not let to set flock's special attributes.
	// Ignore hole request in case we found a flock EAs.
	//

	ANSI_STRING fmName = { 0 };
	RtlInitAnsiString(&fmName, FLOCK_META_NAME);

	PVOID bufferEAs = Data->Iopb->Parameters.SetEa.EaBuffer;
	ULONG bufferEAsLength = Data->Iopb->Parameters.SetEa.Length;
	PMDL mdlEAs = Data->Iopb->Parameters.SetEa.MdlAddress;
	BOOLEAN thisIsAnMdl = FALSE;

	if ( (bufferEAs == NULL) && (mdlEAs != NULL) )
	{
		thisIsAnMdl = TRUE;

		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: ! THIS IS an MDL buffer.\n", __FUNCTION__));
	}

	if (bufferEAs != NULL)
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: ! this is an buffered io.\n", __FUNCTION__));

		for (PFILE_FULL_EA_INFORMATION entry = (PFILE_FULL_EA_INFORMATION)bufferEAs; ;)
		{
			if (entry->EaNameLength == FLOCK_META_NAME_SIZE)
			{
				ANSI_STRING eaName;
				eaName.Length = entry->EaNameLength;
				eaName.MaximumLength = entry->EaNameLength;
				eaName.Buffer = &entry->EaName[0];

				PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: ! Found 10 bytes name entry. NameLength %d ValueLength %d nextEntryOffset %d\n",
					__FUNCTION__,
					entry->EaNameLength,
					entry->EaValueLength,
					entry->NextEntryOffset));

				if (FLockEqualAnsiStrings(&eaName, &fmName))
				{
					//
					// This is a changing of flock-meta EAs. Need to lock hole request.
					//

					//
					// Actually here I have the following cases:
					// - Remove one (our FLOCK_META) attribute and send request further. (Ignore hole request in case we have only single entry in the list).
					// - Change name of our "FLOCK_META" attribute to "FAKE_META" and send the IRP further.
					//

					PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: deny the request - this is an attempt to change FLock meta.\n", __FUNCTION__));

					Data->IoStatus.Status = STATUS_ACCESS_DENIED;
					return FLT_PREOP_COMPLETE;
				}
			}


			if (entry->NextEntryOffset != 0){
				entry = (PFILE_FULL_EA_INFORMATION)(((PUCHAR)entry) + entry->NextEntryOffset);
			} 
			else {
				break;
			}
				
		}
	}

	return FLT_PREOP_SUCCESS_NO_CALLBACK;
}


FLT_POSTOP_CALLBACK_STATUS FLockPostSetEa(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_opt_ PVOID CompletionContext,
	_In_ FLT_POST_OPERATION_FLAGS Flags
	)
{
	UNREFERENCED_PARAMETER(Data);
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(CompletionContext);
	UNREFERENCED_PARAMETER(Flags);

	return FLT_POSTOP_FINISHED_PROCESSING;
}
