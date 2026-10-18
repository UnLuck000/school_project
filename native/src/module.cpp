#include <pybind11/pybind11.h>

#include <cmath>
#include <cstddef>

namespace py = pybind11;

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

PYBIND11_MODULE(_native, m) {
    m.doc() = "Нативные ускорители для антивируса";
    m.def("entropy", &entropy, "Энтропия Шеннона для байтов (0..8)");
}