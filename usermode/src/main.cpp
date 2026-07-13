#include <framework.hpp>
#include <r69-driver/r69_driver.hpp>

int main() {
    std::printf("(+) main\n");

    if (!r69->attach(L"notepad.exe")) {
        std::printf("(-) failed attach\n");
        return 1;
    }
    
    const auto* data = r69->get_attached_process();

    std::printf("(+) process header -> %x\n", r69->read<uint16_t>((uint64_t)data->base_address));

    const auto ntdll = r69->get_process_module_base(L"ntdll.dll");

    std::printf("(+) ntdll : 0x%llx\n", ntdll);

    std::printf("(+) ntdll -> %x\n", r69->read<uint16_t>(ntdll));

    r69->detach();
    
    std::cin.get();

    return 0;
}