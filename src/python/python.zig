pub const py = @cImport({
    @cDefine("PY_SSIZE_T_CLEAN", "1");
    @cDefine("Py_LIMITED_API", "0x030b0000"); // Python 3.11
    @cInclude("Python.h");
});
