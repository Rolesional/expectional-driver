#include <communication/handler.hpp>

namespace {

constexpr uint64_t kPageSize = utils::paging::page_4kb_size;
constexpr uint64_t kPageMask = utils::paging::page_4kb_mask;
constexpr uint64_t kMaxCopyBytes = 0x10000ull; // Expectional usermode cap (driver.cpp)

uint64_t caller_cr3() {
	return __readcr3();
}

uint64_t pointer_to_va(const void* ptr) {
	return reinterpret_cast<uint64_t>(ptr);
}

bool is_user_range(uint64_t va, uint64_t size) {
	if (!va || !size)
		return false;

	if (size > kMaxCopyBytes)
		return false;

	const uint64_t end = va + size;
	if (end < va)
		return false;

	const uint64_t user_limit = static_cast<uint64_t>(MmUserProbeAddress);
	if (va >= user_limit || end > user_limit)
		return false;

	return true;
}

bool phys_copy_in(uint64_t caller_dtb, uint64_t user_va, void* kernel_dst, size_t size) {
	if (!caller_dtb || !user_va || !kernel_dst || !size)
		return false;

	if (!is_user_range(user_va, size))
		return false;

	auto* out = static_cast<uint8_t*>(kernel_dst);
	size_t remaining = size;
	uint64_t va = user_va;

	while (remaining) {
		const size_t page_left = static_cast<size_t>(kPageSize - (va & kPageMask));
		const size_t chunk = min(remaining, page_left);

		const uint64_t phys =
			utils::paging::translate_virtual_to_physical(caller_dtb, va);
		if (!phys)
			return false;

		if (!utils::physical_memory::read(reinterpret_cast<void*>(phys), out, chunk))
			return false;

		remaining -= chunk;
		out += chunk;
		va += chunk;
	}
	return true;
}

bool phys_copy_out(uint64_t caller_dtb, uint64_t user_va, const void* kernel_src, size_t size) {
	if (!caller_dtb || !user_va || !kernel_src || !size)
		return false;

	if (!is_user_range(user_va, size))
		return false;

	const auto* in = static_cast<const uint8_t*>(kernel_src);
	size_t remaining = size;
	uint64_t va = user_va;

	while (remaining) {
		const size_t page_left = static_cast<size_t>(kPageSize - (va & kPageMask));
		const size_t chunk = min(remaining, page_left);

		const uint64_t phys =
			utils::paging::translate_virtual_to_physical(caller_dtb, va);
		if (!phys)
			return false;

		if (!utils::physical_memory::write(const_cast<uint8_t*>(in),
		                                   reinterpret_cast<void*>(phys), chunk))
			return false;

		remaining -= chunk;
		in += chunk;
		va += chunk;
	}
	return true;
}

struct scoped_process_ref {
	PEPROCESS process = nullptr;

	explicit scoped_process_ref(PEPROCESS process_in) : process(process_in) {}

	~scoped_process_ref() {
		if (process)
			ObfDereferenceObject(process);
	}

	scoped_process_ref(const scoped_process_ref&) = delete;
	scoped_process_ref& operator=(const scoped_process_ref&) = delete;
};

bool process_address_space_usable(PEPROCESS process, uint64_t* out_dtb = nullptr) {
	if (!process)
		return false;

	if (PsGetProcessExitStatus(process) != STATUS_PENDING)
		return false;

	const uint64_t dtb = process->DirectoryTableBase;
	if (!dtb)
		return false;

	if (out_dtb)
		*out_dtb = dtb;

	return true;
}

} // namespace

namespace {

NTSTATUS read_process_memory_impl(copy_process_memory_packet* input) {
	if (!input)
		return STATUS_INVALID_PARAMETER;

	if (KeGetCurrentIrql() > PASSIVE_LEVEL)
		return STATUS_INVALID_DEVICE_STATE;

	const uint64_t caller_dtb = caller_cr3();
	if (!caller_dtb)
		return STATUS_UNSUCCESSFUL;

	copy_process_memory_packet req{};
	if (!phys_copy_in(caller_dtb, pointer_to_va(input), &req, sizeof(req)))
		return STATUS_UNSUCCESSFUL;

	if (!req.size || !req.dest || !req.process_id)
		return STATUS_INVALID_PARAMETER;

	if (req.size > kMaxCopyBytes)
		return STATUS_INVALID_PARAMETER;

	if (!is_user_range(req.source, req.size))
		return STATUS_INVALID_PARAMETER;

	if (!is_user_range(pointer_to_va(req.dest), req.size))
		return STATUS_INVALID_PARAMETER;

	PEPROCESS process = nullptr;
	if (!NT_SUCCESS(PsLookupProcessByProcessId(ULongToHandle(req.process_id), &process)))
		return STATUS_UNSUCCESSFUL;

	scoped_process_ref process_guard(process);

	uint64_t target_dtb = 0;
	if (!process_address_space_usable(process, &target_dtb))
		return STATUS_PROCESS_IS_TERMINATING;

	uint64_t remaining = req.size;
	uint64_t game_va = req.source;
	uint64_t user_va = pointer_to_va(req.dest);
	uint8_t chunk[kPageSize];

	while (remaining) {
		if (!process_address_space_usable(process, &target_dtb))
			return STATUS_PROCESS_IS_TERMINATING;

		const size_t game_page_left = static_cast<size_t>(kPageSize - (game_va & kPageMask));
		const size_t user_page_left = static_cast<size_t>(kPageSize - (user_va & kPageMask));
		const size_t step = min(min(remaining, game_page_left), user_page_left);

		const uint64_t game_phys =
			utils::paging::translate_virtual_to_physical(target_dtb, game_va);
		if (!game_phys)
			return STATUS_UNSUCCESSFUL;

		if (!utils::physical_memory::read(reinterpret_cast<void*>(game_phys), chunk, step))
			return STATUS_UNSUCCESSFUL;

		if (!phys_copy_out(caller_dtb, user_va, chunk, step))
			return STATUS_UNSUCCESSFUL;

		remaining -= step;
		game_va += step;
		user_va += step;
	}

	return STATUS_SUCCESS;
}

NTSTATUS query_process_data_impl(query_process_data_packet* input) {
	if (!input)
		return STATUS_INVALID_PARAMETER;

	if (KeGetCurrentIrql() > PASSIVE_LEVEL)
		return STATUS_INVALID_DEVICE_STATE;

	const uint64_t caller_dtb = caller_cr3();
	if (!caller_dtb)
		return STATUS_UNSUCCESSFUL;

	query_process_data_packet req{};
	if (!phys_copy_in(caller_dtb, pointer_to_va(input), &req, sizeof(req)))
		return STATUS_UNSUCCESSFUL;

	if (!req.process_id)
		return STATUS_INVALID_PARAMETER;

	PEPROCESS process = nullptr;
	if (!NT_SUCCESS(PsLookupProcessByProcessId(ULongToHandle(req.process_id), &process)))
		return STATUS_UNSUCCESSFUL;

	scoped_process_ref process_guard(process);

	if (!process_address_space_usable(process))
		return STATUS_PROCESS_IS_TERMINATING;

	req.peb = PsGetProcessPeb(process);
	req.base_address = PsGetProcessSectionBaseAddress(process);
	req.cr3 = process->DirectoryTableBase;

	if (!req.cr3)
		return STATUS_UNSUCCESSFUL;

	if (!phys_copy_out(caller_dtb, pointer_to_va(input), &req, sizeof(req)))
		return STATUS_UNSUCCESSFUL;

	return STATUS_SUCCESS;
}

} // namespace

NTSTATUS handler::read_process_memory(copy_process_memory_packet* input) {
	NTSTATUS status = STATUS_UNSUCCESSFUL;

	__try {
		status = read_process_memory_impl(input);
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		status = STATUS_ACCESS_VIOLATION;
	}

	return status;
}

NTSTATUS handler::write_process_memory(copy_process_memory_packet* input) {
	UNREFERENCED_PARAMETER(input);
	return STATUS_NOT_SUPPORTED;
}

NTSTATUS handler::query_process_data(query_process_data_packet* input) {
	NTSTATUS status = STATUS_UNSUCCESSFUL;

	__try {
		status = query_process_data_impl(input);
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		status = STATUS_ACCESS_VIOLATION;
	}

	return status;
}
