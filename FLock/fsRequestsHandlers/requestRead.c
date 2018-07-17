//
// Author:
//		Burlutsky Stas
//
//		burluckij@gmail.com
//

#include "../flock.h"


// extern PFLT_FILTER gFilterHandle;
// extern ULONG_PTR OperationStatusCtx;
// extern ULONG gTraceFlags;


FLT_PREOP_CALLBACK_STATUS flockPreRead(
	_Inout_ PFLT_CALLBACK_DATA    Data,
	_In_    PCFLT_RELATED_OBJECTS FltObjects,
	_Out_   PVOID                 *CompletionContext
	)
{
	UNREFERENCED_PARAMETER(CompletionContext);
	UNREFERENCED_PARAMETER(Data);
	UNREFERENCED_PARAMETER(FltObjects);

	return FLT_PREOP_SUCCESS_NO_CALLBACK;
}


FLT_POSTOP_CALLBACK_STATUS flockPostRead(
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

//
