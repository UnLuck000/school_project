// Разбор PE-файла для эвристики (scanner/heuristics.py): секции с энтропией, точка входа,
// таблица импорта. Повторяет то, что раньше делал pefile, но без создания тысяч объектов
// Python: файл читается один раз, всё считается при отпущенном GIL.
#include <pybind11/pybind11.h>

#include <algorithm>
#include <cctype>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <string>
#include <vector>

namespace py = pybind11;

namespace {

constexpr size_t MAX_SECTIONS = 96;          // больше в нормальных файлах не бывает
constexpr size_t MAX_DESCRIPTORS = 4096;     // библиотек в таблице импорта
constexpr size_t MAX_THUNKS = 0x2000;        // функций из одной библиотеки (как в pefile)

struct Section {
    std::string name;
    uint32_t characteristics = 0;
    uint32_t raw_size = 0;
    uint32_t virt_size = 0;
    uint32_t virt_addr = 0;
    uint32_t raw_ptr = 0;
    double entropy = -1.0;  // -1: не считалась (секция меньше 1 КБ)
};

struct PeInfo {
    bool ok = false;
    bool dll = false;
    uint32_t entry = 0;
    int entry_section = -1;  // -1: точка входа вне секций
    std::vector<Section> sections;
    std::vector<std::string> imports;  // имена функций в нижнем регистре
    uint32_t total_imports = 0;        // вместе с импортом по номеру
};

template <typename T>
bool read_at(const std::string& data, size_t offset, T& out) {
    if (offset > data.size() || data.size() - offset < sizeof(T)) return false;
    std::memcpy(&out, data.data() + offset, sizeof(T));
    return true;
}

double entropy_of(const unsigned char* p, size_t n) {
    if (n == 0) return 0.0;
    size_t counts[256] = {0};
    for (size_t i = 0; i < n; ++i) ++counts[p[i]];
    double result = 0.0;
    for (size_t c : counts) {
        if (c == 0) continue;
        const double q = static_cast<double>(c) / static_cast<double>(n);
        result -= q * std::log2(q);
    }
    return result;
}

// Выравнивания так же, как в pefile (adjust_SectionAlignment / adjust_FileAlignment)
uint32_t adjust_va(uint32_t va, uint32_t section_align, uint32_t file_align) {
    if (section_align < 0x1000) section_align = file_align;
    if (section_align && va % section_align) return section_align * (va / section_align);
    return va;
}

uint32_t adjust_ptr(uint32_t ptr, uint32_t file_align) {
    if (file_align < 0x200) return ptr;
    return (ptr / 0x200) * 0x200;
}

class Parser {
public:
    Parser(const std::string& data, PeInfo& info) : data_(data), info_(info) {}

    bool run(size_t entropy_limit) {
        uint32_t lfanew = 0;
        if (!read_at(data_, 0x3C, lfanew)) return false;
        uint32_t signature = 0;
        if (!read_at(data_, lfanew, signature) || signature != 0x00004550) return false;  // "PE\0\0"
        const size_t file_header = static_cast<size_t>(lfanew) + 4;
        uint16_t sections = 0, opt_size = 0, characteristics = 0;
        if (!read_at(data_, file_header + 2, sections) ||
            !read_at(data_, file_header + 16, opt_size) ||
            !read_at(data_, file_header + 18, characteristics)) return false;
        info_.dll = (characteristics & 0x2000) != 0;

        const size_t opt = file_header + 20;
        uint16_t magic = 0;
        if (!read_at(data_, opt, magic)) return false;
        const bool pe64 = magic == 0x20B;
        if (!pe64 && magic != 0x10B) return false;
        read_at(data_, opt + 16, info_.entry);
        read_at(data_, opt + 32, section_align_);
        read_at(data_, opt + 36, file_align_);
        const size_t dirs = opt + (pe64 ? 112 : 96);
        uint32_t import_rva = 0, import_size = 0, dir_count = 0;
        read_at(data_, opt + (pe64 ? 108 : 92), dir_count);
        if (dir_count > 1) {
            read_at(data_, dirs + 8, import_rva);
            read_at(data_, dirs + 12, import_size);
        }

        const size_t table = opt + opt_size;
        for (size_t i = 0; i < std::min<size_t>(sections, MAX_SECTIONS); ++i) {
            const size_t h = table + i * 40;
            if (h + 40 > data_.size()) break;
            Section s;
            s.name.assign(data_.data() + h, 8);
            s.name.erase(std::find(s.name.begin(), s.name.end(), '\0'), s.name.end());
            read_at(data_, h + 8, s.virt_size);
            read_at(data_, h + 12, s.virt_addr);
            read_at(data_, h + 16, s.raw_size);
            read_at(data_, h + 20, s.raw_ptr);
            read_at(data_, h + 36, s.characteristics);
            if (s.raw_size >= 1024) {  // как в heuristics.py: из файла, не больше entropy_limit
                const size_t start = std::min<size_t>(s.raw_ptr, data_.size());
                const size_t n = std::min<size_t>({s.raw_size, entropy_limit, data_.size() - start});
                s.entropy = entropy_of(reinterpret_cast<const unsigned char*>(data_.data()) + start, n);
            }
            info_.sections.push_back(std::move(s));
        }
        info_.entry_section = section_of(info_.entry);
        if (import_rva) parse_imports(import_rva, pe64);
        info_.ok = true;
        return true;
    }

private:
    // Секция, в которую попадает RVA (как pefile.get_section_by_rva), или -1
    int section_of(uint32_t rva) const {
        const auto& list = info_.sections;
        for (size_t i = 0; i < list.size(); ++i) {
            const Section& s = list[i];
            const uint32_t va = adjust_va(s.virt_addr, section_align_, file_align_);
            const size_t ptr = adjust_ptr(s.raw_ptr, file_align_);
            uint64_t size = (data_.size() < ptr || data_.size() - ptr < s.raw_size)
                                ? s.virt_size : std::max(s.raw_size, s.virt_size);
            if (i + 1 < list.size()) {  // секция не может заходить на следующую
                const uint32_t next = adjust_va(list[i + 1].virt_addr, section_align_, file_align_);
                if (next > va && va + size > next) size = next - va;
            }
            if (va <= rva && rva < va + size) return static_cast<int>(i);
        }
        return -1;
    }

    // RVA -> смещение в файле; SIZE_MAX, если адрес не отображается на файл
    size_t offset_of(uint32_t rva) const {
        const int i = section_of(rva);
        if (i < 0) {
            if (info_.sections.empty() || rva < info_.sections[0].virt_addr) return rva;  // заголовки
            return SIZE_MAX;
        }
        const Section& s = info_.sections[i];
        const uint32_t va = adjust_va(s.virt_addr, section_align_, file_align_);
        return static_cast<size_t>(rva - va) + adjust_ptr(s.raw_ptr, file_align_);
    }

    std::string c_string(uint32_t rva, size_t limit = 512) const {
        const size_t off = offset_of(rva);
        if (off >= data_.size()) return {};
        const size_t end = std::min(data_.size(), off + limit);
        const char* begin = data_.data() + off;
        const char* zero = static_cast<const char*>(std::memchr(begin, 0, end - off));
        return std::string(begin, zero ? zero : data_.data() + end);
    }

    void parse_imports(uint32_t import_rva, bool pe64) {
        size_t desc = offset_of(import_rva);
        for (size_t d = 0; d < MAX_DESCRIPTORS && desc != SIZE_MAX; ++d, desc += 20) {
            uint32_t original = 0, name_rva = 0, first = 0;
            if (!read_at(data_, desc, original) || !read_at(data_, desc + 12, name_rva) ||
                !read_at(data_, desc + 16, first)) break;
            if (!original && !name_rva && !first) break;  // пустой дескриптор: конец таблицы
            const uint32_t thunk_rva = original ? original : first;
            size_t thunk = offset_of(thunk_rva);
            if (thunk == SIZE_MAX) continue;
            const size_t step = pe64 ? 8 : 4;
            for (size_t t = 0; t < MAX_THUNKS; ++t, thunk += step) {
                uint64_t value = 0;
                if (pe64) {
                    if (!read_at(data_, thunk, value)) break;
                } else {
                    uint32_t v32 = 0;
                    if (!read_at(data_, thunk, v32)) break;
                    value = v32;
                }
                if (value == 0) break;
                ++info_.total_imports;
                const uint64_t ordinal_flag = pe64 ? 0x8000000000000000ULL : 0x80000000ULL;
                if (value & ordinal_flag) continue;  // импорт по номеру: имени нет
                std::string name = c_string(static_cast<uint32_t>(value & 0x7FFFFFFF) + 2);
                if (name.empty()) continue;
                std::transform(name.begin(), name.end(), name.begin(),
                               [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
                info_.imports.push_back(std::move(name));
            }
        }
    }

    const std::string& data_;
    PeInfo& info_;
    uint32_t section_align_ = 0;
    uint32_t file_align_ = 0;
};

}  // namespace

// Возвращает словарь со сведениями о PE или None (не PE, слишком большой, не прочитан)
py::object pe_info(const std::wstring& path, size_t entropy_limit, size_t max_size) {
    PeInfo info;
    {
        py::gil_scoped_release release;  // объекты Python здесь не трогаем
        std::ifstream file(path, std::ios::binary | std::ios::ate);
        const auto size = file ? static_cast<size_t>(file.tellg()) : 0;
        if (file && size >= 64 && size <= max_size) {
            std::string data(size, '\0');
            file.seekg(0);
            file.read(data.data(), static_cast<std::streamsize>(size));
            if (static_cast<size_t>(file.gcount()) == size && data[0] == 'M' && data[1] == 'Z') {
                Parser(data, info).run(entropy_limit);
            }
        }
    }
    if (!info.ok) return py::none();
    py::list sections;
    for (const Section& s : info.sections) {
        sections.append(py::make_tuple(py::bytes(s.name), s.characteristics, s.raw_size,
                                       s.virt_size, s.entropy));
    }
    py::list imports;
    for (const std::string& name : info.imports) imports.append(py::str(name));
    py::dict result;
    result["dll"] = info.dll;
    result["entry"] = info.entry;
    result["entry_section"] = info.entry_section;
    result["sections"] = sections;
    result["imports"] = imports;
    result["total_imports"] = info.total_imports;
    return result;
}
