#include <hooks/hooks.hpp>
#include <communication/communication.hpp>

namespace {

bool is_expectional_communication_request() {
	if (KeGetCurrentIrql() > PASSIVE_LEVEL)
		return false;

	PKTHREAD thread = KeGetCurrentThread();
	if (!thread)
		return false;

	PKTRAP_FRAME trap_frame = thread->TrapFrame;
	if (!trap_frame || !MmIsAddressValid(trap_frame))
		return false;

	auto* packet = reinterpret_cast<c_packet*>(trap_frame->Rdx);
	if (!packet)
		return false;

	__try {
		ProbeForRead(packet, sizeof(c_packet), sizeof(void*));
		const auto syscall = packet->get_syscall();
		return syscall == e_syscall::read_process_memory || syscall == e_syscall::write_process_memory ||
		       syscall == e_syscall::query_process_data;
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		return false;
	}
}

} // namespace

NTSTATUS hooks::hal_timer_query_auxiliary_counter_frequency::hook_handler(uint64_t* counter) {
	/** Kernel / HAL gercek cagrilari: orijinal fonksiyona devret (TrapFrame yok -> corruption riski). */
	if (!is_expectional_communication_request()) {
		if (o_function)
			return o_function(counter);
		return STATUS_NOT_IMPLEMENTED;
	}

	return communication::communication_handler(KeGetCurrentThread()->TrapFrame);
}
