#include <pybind11/pybind11.h>

#include <cmath>
#include <cstddef>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif

namespace py = pybind11;

// pe.cpp
py::object pe_info(const std::wstring& path, size_t entropy_limit, size_t max_size);

// Принимает bytes, bytearray или memoryview
static double entropy(py::buffer buf) {
    py::buffer_info info = buf.request();
    const auto* data = static_cast<const unsigned char*>(info.ptr);
    const size_t n = static_cast<size_t>(info.size) * static_cast<size_t>(info.itemsize);
    if (n == 0) return 0.0;

    py::gil_scoped_release release;  // другие потоки Python работают, пока считаем

    size_t counts[256] = {0};
    for (size_t i = 0; i < n; ++i) ++counts[data[i]];

    double result = 0.0;
    const double total = static_cast<double>(n);
    for (size_t c : counts) {
        if (c == 0) continue;
        const double p = static_cast<double>(c) / total;
        result -= p * std::log2(p);
    }
    return result;
}

#ifdef _WIN32
// Регион памяти, прочитанный из чужого процесса
struct Chunk {
    uint64_t base;
    std::string data;
};

// Читает регион целиком, а если не вышло (часть страниц недоступна), то по 64 КБ:
// нечитаемые куски пропускаются, остальное сохраняется отдельными блоками.
static void read_region(HANDLE process, uint64_t base, size_t size, std::vector<Chunk>& out,
                        size_t& total, size_t max_total) {
    std::string buffer(size, '\0');
    SIZE_T got = 0;
    if (ReadProcessMemory(process, reinterpret_cast<LPCVOID>(base), buffer.data(), size, &got)
        && got > 0) {
        buffer.resize(got);
        total += got;
        out.push_back({base, std::move(buffer)});
        return;
    }
    const size_t step = 64 * 1024;
    for (size_t offset = 0; offset < size && total < max_total; offset += step) {
        const size_t part = (size - offset < step) ? size - offset : step;
        std::string piece(part, '\0');
        got = 0;
        if (ReadProcessMemory(process, reinterpret_cast<LPCVOID>(base + offset), piece.data(),
                              part, &got) && got > 0) {
            piece.resize(got);
            total += got;
            out.push_back({base + offset, std::move(piece)});
        }
    }
}

// Читает из процесса то, что стоит проверять правилами YARA: приватную память
// (MEM_PRIVATE: кучи, стеки, внедрённый код) и, по желанию, образы модулей с правами
// RWX (распакованный код). Отображённые файлы и обычные модули не читаются: их
// содержимое лежит на диске и проверяется сканером файлов, а именно они занимают
// бо́льшую часть памяти процесса.
// Читает порцию не больше max_total байт, начиная с адреса start: так поток проверки
// держит в памяти только одну порцию, а не всю память процесса сразу.
// Возвращает (список (адрес, bytes), адрес продолжения или 0, если дочитано до конца).
// OSError, если процесс нельзя открыть.
static py::tuple read_regions(uint32_t pid, size_t max_region, size_t max_total,
                              bool rwx_images, uint64_t start) {
    std::vector<Chunk> chunks;
    DWORD error = 0;
    uint64_t next = 0;
    {
        py::gil_scoped_release release;  // чтение памяти идёт без блокировки интерпретатора
        HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
        if (process == nullptr) {
            error = GetLastError();
        } else {
            MEMORY_BASIC_INFORMATION mbi;
            uint64_t address = start;
            size_t total = 0;
            while (VirtualQueryEx(process, reinterpret_cast<LPCVOID>(address), &mbi,
                                  sizeof(mbi)) == sizeof(mbi)) {
                const uint64_t base = reinterpret_cast<uint64_t>(mbi.BaseAddress);
                const size_t size = mbi.RegionSize;
                const DWORD protect = mbi.Protect;
                const bool readable = mbi.State == MEM_COMMIT
                    && !(protect & (PAGE_GUARD | PAGE_NOACCESS)) && protect != 0;
                const bool wanted = mbi.Type == MEM_PRIVATE
                    || (rwx_images && mbi.Type == MEM_IMAGE
                        && (protect & 0xFF) == PAGE_EXECUTE_READWRITE);
                if (readable && wanted && size <= max_region) {
                    if (total > 0 && total + size > max_total) {
                        next = base;  // регион не помещается в порцию: он будет следующим
                        break;
                    }
                    read_region(process, base, size < max_total ? size : max_total, chunks,
                                total, max_total);
                }
                if (size == 0) break;
                address = base + size;
            }
            CloseHandle(process);
        }
    }
    if (error != 0) {
        PyErr_SetFromWindowsErr(static_cast<int>(error));
        throw py::error_already_set();
    }
    py::list result;
    for (auto& chunk : chunks) {
        result.append(py::make_tuple(chunk.base, py::bytes(chunk.data)));
    }
    return py::make_tuple(result, next);
}
#endif

PYBIND11_MODULE(_native, m) {
    m.doc() = "Нативные ускорители для антивируса";
    m.def("entropy", &entropy, "Энтропия Шеннона для байтов (0..8)");
    m.def("pe_info", &pe_info, py::arg("path"), py::arg("entropy_limit"), py::arg("max_size"),
          "Сведения о PE для эвристики: секции с энтропией, точка входа, импорт; None — не PE");
#ifdef _WIN32
    m.def("read_regions", &read_regions, py::arg("pid"), py::arg("max_region"),
          py::arg("max_total"), py::arg("rwx_images") = true, py::arg("start") = 0,
          "Порция приватной памяти процесса для YARA: ([(адрес, bytes)], адрес продолжения)");
#endif
}
