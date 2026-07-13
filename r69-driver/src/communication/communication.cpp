#include <communication/communication.hpp>

namespace {

NTSTATUS dispatch_syscall(c_packet* packet) {
	if (!packet)
		return STATUS_INVALID_PARAMETER;

	const auto syscall = packet->get_syscall();
	NTSTATUS status = STATUS_SUCCESS;

	switch (syscall) {
	case e_syscall::read_process_memory: {
		auto* payload = packet->get<copy_process_memory_packet>();
		if (!payload)
			return STATUS_INVALID_PARAMETER;
		__try {
			ProbeForRead(payload, sizeof(copy_process_memory_packet), sizeof(uint32_t));
			status = handler::read_process_memory(payload);
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			status = STATUS_ACCESS_VIOLATION;
		}
		break;
	}
	case e_syscall::write_process_memory: {
		auto* payload = packet->get<copy_process_memory_packet>();
		if (!payload)
			return STATUS_INVALID_PARAMETER;
		__try {
			ProbeForRead(payload, sizeof(copy_process_memory_packet), sizeof(uint32_t));
			status = handler::write_process_memory(payload);
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			status = STATUS_ACCESS_VIOLATION;
		}
		break;
	}
	case e_syscall::query_process_data: {
		auto* payload = packet->get<query_process_data_packet>();
		if (!payload)
			return STATUS_INVALID_PARAMETER;
		__try {
			ProbeForRead(payload, sizeof(query_process_data_packet), sizeof(uint32_t));
			status = handler::query_process_data(payload);
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			status = STATUS_ACCESS_VIOLATION;
		}
		break;
	}
	case e_syscall::null:
	default:
		status = STATUS_INVALID_PARAMETER;
		break;
	}

	return status;
}

} // namespace

NTSTATUS communication::communication_handler(PKTRAP_FRAME trap_frame) {
	if (!trap_frame || !MmIsAddressValid(trap_frame))
		return STATUS_INVALID_PARAMETER;

	if (KeGetCurrentIrql() > PASSIVE_LEVEL)
		return STATUS_INVALID_DEVICE_STATE;

	auto* packet = reinterpret_cast<c_packet*>(trap_frame->Rdx);
	if (!packet)
		return STATUS_INVALID_PARAMETER;

	__try {
		ProbeForRead(packet, sizeof(c_packet), sizeof(void*));
		return dispatch_syscall(packet);
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		return STATUS_ACCESS_VIOLATION;
	}
}
