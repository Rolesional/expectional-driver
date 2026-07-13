#include <utils/memory.hpp>

namespace {

constexpr uint64_t kMaxPhysicalAddress = 0x000FFFFFFFFFFFFull;

bool is_plausible_physical(uint64_t address, size_t size) {
    if (!address || !size)
        return false;

    const uint64_t end = address + size;
    if (end < address)
        return false;

    if (address > kMaxPhysicalAddress || end > kMaxPhysicalAddress)
        return false;

    return true;
}

} // namespace

bool utils::physical_memory::read(void* src, void* dst, const size_t size,
    size_t* bytes_transferred) {
    if (!src || !dst || !size)
        return false;

    const uint64_t physical = static_cast<uint64_t>(reinterpret_cast<uintptr_t>(src));
    if (!is_plausible_physical(physical, size))
        return false;

    size_t temp_bytes_transferred = 0;
    bool ok = false;

    __try {
        MM_COPY_ADDRESS mm_copy_address = {};
        mm_copy_address.PhysicalAddress.QuadPart = physical;
        ok = NT_SUCCESS(MmCopyMemory(dst, mm_copy_address, size,
            MM_COPY_MEMORY_PHYSICAL,
            &temp_bytes_transferred));
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        ok = false;
        temp_bytes_transferred = 0;
    }

    if (bytes_transferred)
        *bytes_transferred = temp_bytes_transferred;

    return ok;
}

bool utils::physical_memory::write(void* src, void* dst, const size_t size,
    size_t* bytes_transferred) {
    if (!src || !dst || !size)
        return false;

    const uint64_t physical = static_cast<uint64_t>(reinterpret_cast<uintptr_t>(dst));
    if (!is_plausible_physical(physical, size))
        return false;

    bool ok = false;

    __try {
        PHYSICAL_ADDRESS physical_address = {};
        physical_address.QuadPart = physical;

        auto* mapped_memory = MmMapIoSpaceEx(physical_address, size, PAGE_READWRITE);
        if (!mapped_memory) {
            ok = false;
        } else {
            if (memcpy(mapped_memory, src, size) != mapped_memory) {
                MmUnmapIoSpace(mapped_memory, size);
                ok = false;
            } else {
                MmUnmapIoSpace(mapped_memory, size);
                ok = true;
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        ok = false;
    }

    if (ok && bytes_transferred)
        *bytes_transferred = size;

    return ok;
}

bool utils::physical_memory::read(void* src, void* dst, const size_t size) {
    return read(src, dst, size, nullptr);
}

bool utils::physical_memory::write(void* src, void* dst, const size_t size) {
    return write(src, dst, size, 
        nullptr);
}

void* utils::physical_memory::get_physical_for_virtual(void* virtual_address) {
    return (void*)MmGetPhysicalAddress(virtual_address).QuadPart;
}

void* utils::physical_memory::get_virtual_for_physical(void* physical_address) {
    return MmGetVirtualForPhysical(PHYSICAL_ADDRESS{ .QuadPart = (int64_t)physical_address});
}

bool utils::virtual_memory::read(void* src, void* dst, const size_t size,
    size_t* bytes_transferred) {
    if (!src || !dst || !size)
        return false;

    size_t temp_bytes_transferred = 0;

    MM_COPY_ADDRESS mm_copy_address = {};
    mm_copy_address.VirtualAddress = src;
    const auto status = NT_SUCCESS(MmCopyMemory(dst, mm_copy_address, size,
        MM_COPY_MEMORY_VIRTUAL,
        &temp_bytes_transferred));

    if (bytes_transferred)
        *bytes_transferred = temp_bytes_transferred;

    return status;
}

bool utils::virtual_memory::write(void* src, void* dst, const size_t size,
    size_t* bytes_transferred) {
    if (!src || !dst || !size)
        return false;

    size_t temp_bytes_transferred = 0;

    MM_COPY_ADDRESS mm_copy_address = {};
    mm_copy_address.VirtualAddress = src;
    const auto status = NT_SUCCESS(MmCopyMemory(dst, mm_copy_address, size,
        MM_COPY_MEMORY_VIRTUAL,
        &temp_bytes_transferred));

    if (bytes_transferred)
        *bytes_transferred = temp_bytes_transferred;

    return status;
}

bool utils::virtual_memory::read(void* src, void* dst, const size_t size) {
    return read(src, dst, size, nullptr);
}

bool utils::virtual_memory::write(void* src, void* dst, const size_t size) {
    return write(src, dst, size, nullptr);
}