const std = @import("std");

const py = @cImport({
    @cDefine("PY_SSIZE_T_CLEAN", "1");
    @cDefine("Py_LIMITED_API", "0x030b0000"); // Python 3.11
    @cInclude("Python.h");
});

const umac = @import("root.zig");


fn getSliceFromPyBytes(obj: [*c]py.PyObject) ?[]const u8 {
    var ptr: [*]u8 = undefined;
    var size: isize = 0;

    if (py.PyBytes_AsStringAndSize(obj, @ptrCast(&ptr), &size) != 0) return null;

    return ptr[0..@intCast(size)];
}


fn createModuleDef(name: []const u8) py.PyModuleDef {
    return .{
        // See: https://github.com/python/cpython/blob/3.14/Include/moduleobject.h#L60
        .m_base = .{
            .ob_base = .{
                .unnamed_0 = .{
                    .ob_refcnt_full = @as(i64, @bitCast(@as(c_longlong, @as(py.Py_ssize_t, @bitCast(@as(c_ulong, @truncate(@as(c_ulonglong, 3) << @intCast(30))))) | (@as(py.Py_ssize_t, @bitCast(@as(c_long, @as(c_int, 4) | @as(c_int, 1)))) << @intCast(48))))),
                },
            },
        },
        .m_name = @ptrCast(name),
    };
}


var module_def = createModuleDef("umac");


const UMAC = struct {
    ob_base: py.PyObject,
    umac: umac.Umac,
};

var umac_methods = [_]py.PyMethodDef{
    .{
        .ml_name = "update",
        .ml_meth = @ptrCast(&UMACUpdate),
        .ml_flags = py.METH_VARARGS | py.METH_KEYWORDS,
    },
    .{
        .ml_name = "digest",
        .ml_meth = @ptrCast(&UMACDigest),
        .ml_flags = py.METH_NOARGS,
    },
    .{ .ml_name = null }, // Sentinel
};

fn repr(obj: [*c]py.PyObject) void {
    const repr_ptr = py.PyObject_Repr(obj);
    defer py.Py_DECREF(repr_ptr);

    var size: isize = undefined;
    const ptr = py.PyUnicode_AsUTF8AndSize(repr_ptr, &size);
    const string = ptr[0..@intCast(size)];

    std.debug.print("repr: {s}\n", .{string});
}

fn UMACNew(_: *anyopaque, args: [*c]py.PyObject, kwargs: [*c]py.PyObject) callconv(.c) [*c]py.PyObject {
    var tag_len: u8 = undefined;
    var nonce_buffer: py.Py_buffer = undefined;
    var key_buffer: py.Py_buffer = undefined;

    const keywords = [_][*c]const u8{
        "digest_size",
        "key",
        "nonce",
        null,
    };

    if (
        py.PyArg_ParseTupleAndKeywords(
            args,
            kwargs,
            "by*y*",
            @ptrCast(&keywords),
            &tag_len,
            &key_buffer,
            &nonce_buffer,
        ) == 0
    ) return null;

    const key_ptr: [*]const u8 = @ptrCast(key_buffer.buf);
    const key = key_ptr[0..@intCast(key_buffer.len)];

    const nonce_ptr: [*]const u8 = @ptrCast(nonce_buffer.buf);
    const nonce = nonce_ptr[0..@intCast(nonce_buffer.len)];

    if (tag_len != 4 and tag_len != 8 and tag_len != 12 and tag_len != 16) {
        py.PyErr_SetString(py.PyExc_ValueError, "Invalid digest size");
        py.PyBuffer_Release(&nonce_buffer);
        py.PyBuffer_Release(&key_buffer);
        return null;
    }

    if (key.len != umac.KEY_LEN) {
        py.PyErr_SetString(py.PyExc_ValueError, std.fmt.comptimePrint("Invalid key length, must be {d}", .{umac.KEY_LEN}));
        py.PyBuffer_Release(&nonce_buffer);
        py.PyBuffer_Release(&key_buffer);
        return null;
    }

    if (nonce.len <= 0 or nonce.len > umac.BLOCK_LEN) {
        py.PyErr_SetString(py.PyExc_ValueError, std.fmt.comptimePrint("Invalid nonce length, must be between 1 and {} included", .{umac.BLOCK_LEN}));
        py.PyBuffer_Release(&nonce_buffer);
        py.PyBuffer_Release(&key_buffer);
        return null;
    }

    const obj = py.PyType_GenericNew(@ptrCast(umac_type), null, null) orelse return null;

    const self: *UMAC = @ptrCast(obj);
    self.umac = umac.Umac.init(tag_len, key[0..umac.KEY_LEN], nonce);

    return obj;
}

fn UMACUpdate(instance: [*c]py.PyObject, args: [*c]py.PyObject, kwargs: [*c]py.PyObject) callconv(.c) [*c]py.PyObject {
    var part_buffer: py.Py_buffer = undefined;

    const keywords = [_][*c]const u8{"", null};

    if (
        py.PyArg_ParseTupleAndKeywords(
            args,
            kwargs,
            "y*",
            @ptrCast(&keywords),
            &part_buffer,
        ) == 0
    ) return null;

    const part_ptr: [*]const u8 = @ptrCast(part_buffer.buf);
    const part = part_ptr[0..@intCast(part_buffer.len)];

    const self: *UMAC = @ptrCast(instance);
    self.umac.update(part);

    return py.Py_None();
}

fn UMACDigest(instance: [*c]py.PyObject, _: [*c]py.PyObject) callconv(.c) [*c]py.PyObject {
    const self: *UMAC = @ptrCast(instance);

    const digest = py.PyBytes_FromStringAndSize(null, @intCast(self.umac.tag_len)) orelse return null;
    self.umac.finish(py.PyBytes_AsString(digest));

    return digest;
}

var umac_type_slots = [_]py.PyType_Slot{
    .{ .slot = py.Py_tp_methods, .pfunc = @ptrCast(&umac_methods) },
    .{ .slot = py.Py_tp_new, .pfunc = @constCast(&UMACNew) },
    .{ .slot = 0, .pfunc = null }, // Sentinel
};

var umac_type_spec = py.PyType_Spec{
    .name = "umac.UMAC",
    .basicsize = @sizeOf(UMAC),
    .itemsize = 0,
    .flags = py.Py_TPFLAGS_DEFAULT,
    .slots = &umac_type_slots,
};

var umac_type: *anyopaque = undefined;


export fn PyInit_umac() [*c]py.PyObject {
    umac_type = py.PyType_FromSpec(&umac_type_spec) orelse return null;
    if (py.PyType_Ready(@ptrCast(umac_type)) < 0) return null;

    const module = py.PyModule_Create(&module_def) orelse return null;

    if (py.PyModule_AddObjectRef(module, "UMAC", @ptrCast(@alignCast(umac_type))) < 0) {
        py.Py_DECREF(module);
        return null;
    }

    return module;
}
