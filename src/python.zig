const std = @import("std");

const py = @cImport({
    @cDefine("PY_SSIZE_T_CLEAN", "1");
    @cDefine("Py_LIMITED_API", "0x030b0000"); // Python 3.11
    @cInclude("Python.h");
});


var moduleDef: py.PyModuleDef = .{
    // See: https://github.com/python/cpython/blob/3.14/Include/moduleobject.h#L60
    .m_base = .{
        .ob_base = .{
            .unnamed_0 = .{
                .ob_refcnt_full = @as(i64, @bitCast(@as(c_longlong, @as(py.Py_ssize_t, @bitCast(@as(c_ulong, @truncate(@as(c_ulonglong, 3) << @intCast(30))))) | (@as(py.Py_ssize_t, @bitCast(@as(c_long, @as(c_int, 4) | @as(c_int, 1)))) << @intCast(48))))),
            },
            .ob_type = null,
        },
        .m_init = null,
        .m_index = @as(py.Py_ssize_t, @bitCast(@as(c_long, @as(c_int, 0)))),
        .m_copy = null,
    },
    .m_name = "dxffmpeg",
    .m_doc = null,
    .m_size = @as(py.Py_ssize_t, @bitCast(@as(c_long, @as(c_int, 0)))),
    .m_methods = null,
    .m_slots = null,
    .m_traverse = @import("std").mem.zeroes(py.traverseproc),
    .m_clear = @import("std").mem.zeroes(py.inquiry),
    .m_free = @import("std").mem.zeroes(py.freefunc),
};


export fn PyInit_umac() [*c]py.PyObject {
    const module = py.PyModule_Create(&moduleDef) orelse return null;

    return module;
}
