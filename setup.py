from pybind11.setup_helpers import Pybind11Extension, build_ext
from setuptools import setup

setup(
    name="sbit-native",
    ext_modules=[Pybind11Extension("scanner._native", ["native/src/module.cpp", "native/src/pe.cpp"], cxx_std=17)],
    cmdclass={"build_ext": build_ext},
)
