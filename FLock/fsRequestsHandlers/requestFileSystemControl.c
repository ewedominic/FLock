//
// Author:
//		Burlutsky Stas
//
//		burluckij@gmail.com
//

#include "../flock.h"

extern ULONG gTraceFlags;


FLT_PREOP_CALLBACK_STATUS FLockPreFsControl(
	_Inout_ PFLT_CALLBACK_DATA    Data,
	_In_    PCFLT_RELATED_OBJECTS FltObjects,
	_Out_   PVOID                 *CompletionContext
	)
{
	UNREFERENCED_PARAMETER(CompletionContext);
	UNREFERENCED_PARAMETER(Data);
	UNREFERENCED_PARAMETER(FltObjects);

	//
	// Thats an attempt to open a hard drive on low-level.
	//

	if (BooleanFlagOn(FltObjects->FileObject->Flags, FO_VOLUME_OPEN))
	{
		//
		// Verify in settings access details.
		//

		// ...

		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FLock!%s: an attempt to open volume.\n", __FUNCTION__));

		//Data->IoStatus.Status = STATUS_ACCESS_DENIED;
		//return FLT_PREOP_COMPLETE;
	}

	return FLT_PREOP_SUCCESS_NO_CALLBACK;
}


FLT_POSTOP_CALLBACK_STATUS FLockPostFsControl(
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
