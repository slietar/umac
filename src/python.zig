const std = @import("std");

const py = @cImport({
    @cDefine("PY_SSIZE_T_CLEAN", "1");
    @cDefine("Py_LIMITED_API", "0x030b0000"); // Python 3.11
    @cInclude("Python.h");
});

const umac = @import("root.zig");


// const AESFactory = struct {
//     ptr: *const fn (key: []const u8) *AES,
//     build: *const fn (key: *const [umac.KEY_LEN]u8) AES,
// };

fn getSliceFromPyBytes(obj: [*c]py.PyObject) ?[]const u8 {
    var ptr: [*]u8 = undefined;
    var size: isize = 0;

    if (py.PyBytes_AsStringAndSize(obj, @ptrCast(&ptr), &size) != 0) return null;

    return ptr[0..@intCast(size)];
}


// const CryptographyAES = struct {
//     encryptor: [*c]py.PyObject,
// };

// fn CryptographyAESEncrypt(self: *CryptographyAES, block_in: *const [umac.BLOCK_LEN]u8, block_out: *[umac.BLOCK_LEN]u8) void {
//     const input_bytes = py.PyBytes_FromStringAndSize(@ptrCast(block_in), umac.BLOCK_LEN) orelse @panic("Failed to create input bytes");
//     defer py.Py_DECREF(input_bytes);

//     const result_1 = py.PyObject_CallMethod(self.encryptor, "update", "O", input_bytes) orelse @panic("Failed to call update");
//     defer py.Py_DECREF(result_1);

//     const result_2 = py.PyObject_CallMethod(self.encryptor, "finalize", null) orelse @panic("Failed to call finalize");
//     defer py.Py_DECREF(result_2);

//     var result_1_size: isize = 0;
//     var result_1_ptr: [*]u8 = undefined;

//     if (py.PyBytes_AsStringAndSize(result_1, @ptrCast(&result_1_ptr), &result_1_size) != 0) @panic("Failed to get bytes data");
//     // const result_2_ptr = py.PyBytes_AsString(result_2) orelse @panic("Failed to get bytes data");

//     const chunk2 = getSliceFromPyBytes(result_2) orelse @panic("Failed to get bytes data");
//     const split: usize = @intCast(result_1_size);

//     @memcpy(block_out[0..split], result_1_ptr[0..split]);
//     @memcpy(block_out[split..umac.BLOCK_LEN], chunk2[0..(umac.BLOCK_LEN - split)]);
// }

// fn CryptographyAESFree(self: *CryptographyAES) void {
//     py.Py_DECREF(self.encryptor);
//     py.PyMem_Free(self);
// }


// const CryptographyAESFactory = struct {
//     aes_class: [*c]py.PyObject,
// };

// fn getCryptographyAES(key: *const [umac.KEY_LEN]u8) ?AESInterface {
//     const algorithms_module = py.PyImport_ImportModule("cryptography.hazmat.primitives.ciphers.algorithms") orelse return null;
//     defer py.Py_DECREF(algorithms_module);

//     const aes_class = py.PyObject_GetAttrString(algorithms_module, "AES") orelse return null;
//     defer py.Py_DECREF(aes_class);

//     const ciphers_module = py.PyImport_ImportModule("cryptography.hazmat.primitives.ciphers") orelse return null;
//     defer py.Py_DECREF(ciphers_module);

//     const cipher_class = py.PyObject_GetAttrString(ciphers_module, "Cipher") orelse return null;
//     defer py.Py_DECREF(cipher_class);

//     const modes_module = py.PyImport_ImportModule("cryptography.hazmat.primitives.ciphers.modes") orelse return null;
//     defer py.Py_DECREF(modes_module);

//     const ecb_class = py.PyObject_GetAttrString(modes_module, "ECB") orelse return null;
//     defer py.Py_DECREF(ecb_class);

//     const aes_instance = py.PyObject_CallFunctionObjArgs(
//         aes_class,
//         py.PyBytes_FromStringAndSize(@ptrCast(key), umac.KEY_LEN),
//         @as([*c]const u8, null),
//     ) orelse @panic("Failed to create instance");

//     const ecb_instance = py.PyObject_CallFunctionObjArgs(
//         ecb_class,
//         @as([*c]const u8, null),
//     ) orelse return null;

//     const cipher_instance = py.PyObject_CallFunctionObjArgs(
//         cipher_class,
//         aes_instance,
//         ecb_instance,
//         @as([*c]const u8, null),
//     ) orelse return null;

//     // End of factory

//     const encryptor = py.PyObject_CallMethod(cipher_instance, "encryptor", null) orelse return null;

//     const aes: *CryptographyAES = @ptrCast(@alignCast(py.PyMem_Malloc(@sizeOf(CryptographyAES))));
//     aes.*.encryptor = encryptor;

//     return AESInterface{
//         .ptr = aes,
//         .encrypt = @ptrCast(&CryptographyAESEncrypt),
//         .free = @ptrCast(&CryptographyAESFree),
//     };
// }


// const CryptographyEncryptor = struct { };


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
    umac: umac.Umac(umac.OpenSSLEncryptor, 4),
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
    var tag_len_bits: u8 = undefined;
    var nonce_buffer: py.Py_buffer = undefined;
    var key_buffer: py.Py_buffer = undefined;

    const keywords = [_][*c]const u8{
        "size",
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
            &tag_len_bits,
            &key_buffer,
            &nonce_buffer,
        ) == 0
    ) return null;

    const key_ptr: [*]const u8 = @ptrCast(key_buffer.buf);
    const key = key_ptr[0..@intCast(key_buffer.len)];

    const nonce_ptr: [*]const u8 = @ptrCast(nonce_buffer.buf);
    const nonce = nonce_ptr[0..@intCast(nonce_buffer.len)];

    if (tag_len_bits != 32 and tag_len_bits != 64 and tag_len_bits != 96 and tag_len_bits != 128) {
        py.PyErr_SetString(py.PyExc_ValueError, "Invalid tag size. Must be one of 32, 64, 96, 128.");
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

    const tag_len = @divExact(tag_len_bits, 8);
    _ = tag_len;

    const obj = py.PyType_GenericNew(@ptrCast(umac_type), null, null) orelse return null;

    const self: *UMAC = @ptrCast(obj);
    self.umac = umac.Umac(umac.OpenSSLEncryptor, 4).init(key[0..umac.KEY_LEN], nonce);

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

    const tag = self.umac.finish();
    return py.PyBytes_FromStringAndSize(@ptrCast(&tag), tag.len) orelse return null;
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
