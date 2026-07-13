#include <framework.hpp>
#include <hooks/hooks.hpp>

NTSTATUS FxDriverEntry(PDRIVER_OBJECT, PUNICODE_STRING) {
	hooks::initialize();
	return STATUS_SUCCESS;
}