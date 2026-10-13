// Exercise the actual bridge with a fake native boundary: no client or Frida required.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const { test } = require('node:test');

class Pointer {
    constructor(bytes, offset = 0) { this.bytes = bytes; this.offset = offset; }
    add(n) { return new Pointer(this.bytes, this.offset + n); }
    writeByteArray(a) { this.bytes.set(new Uint8Array(a), this.offset); }
    readByteArray(n) { return this.bytes.slice(this.offset, this.offset + n).buffer; }
    readU8() { return this.bytes[this.offset]; }
    readU16() { return new DataView(this.bytes.buffer).getUint16(this.offset, true); }
    readU32() { return new DataView(this.bytes.buffer).getUint32(this.offset, true); }
    writeU32(n) { new DataView(this.bytes.buffer).setUint32(this.offset, n, true); }
}

test('only compressed bytes beyond the clear prefix reach the native callback', () => {
    for (const size of [17, 129]) {
        const header = new Uint8Array(104);
        const fields = new DataView(header.buffer);
        fields.setUint16(8, 128, true);
        fields.setUint32(12, 129, true); // Padded body can extend beyond the clear prefix.
        fields.setUint32(16, size, true);
        fields.setUint32(20, size, true);
        let calls = 0;
        const context = {
            rpc: { exports: {} }, Uint8Array, send() {},
            Memory: { copy(dst, src, n) { dst.writeByteArray(src.readByteArray(n)); } },
            fake: {
                buffer(_name, n) { return new Pointer(new Uint8Array(n)); },
                hash() {}, // Hash and header cryptography are tested by decoder vectors.
                header(_obj, _hash, _input, _size, output) { output.writeByteArray(header); return true; },
                callbacks: new Map([[128, (...args) => {
                    calls++;
                    assert.equal(args[8], 1, 'never pass a negative length to an unsigned native argument');
                    return true;
                }]]), keys: new Map(),
            },
        };
        vm.createContext(context);
        vm.runInContext(fs.readFileSync(`${__dirname}/../src/grf_extractor/native/native-decoder.js`, 'utf8'), context);
        vm.runInContext('nativeDecoder = fake', context);
        const output = context.rpc.exports.decodeEntry([97], size, new ArrayBuffer(104 + 129));
        assert.equal(output.byteLength, size);
        assert.equal(calls, size > 128 ? 1 : 0);
    }
});
