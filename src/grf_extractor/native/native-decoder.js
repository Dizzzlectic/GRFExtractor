// Appended to the pinned Unlicense frida.js by native/decoder.py.
// Addresses refer to the executable identified in client-profile.json.
let nativeDecoder = null;
let exitRegistrationStub = null;

rpc.exports.initializeDecoder = function (archiveKeys = []) {
    const module = Process.getModuleByName('Ragexe.exe');
    const address = va => module.base.add(va - 0x400000);
    Memory.protect(module.base.add(0x1000), 0xda8200, 'rwx');

    // Only the two cipher initializers run. The main game thread stays at OEP.
    // CRT exit registration is not ready at that point in startup.
    exitRegistrationStub = new NativeCallback(() => 0, 'int', ['pointer'], 'mscdecl');
    Interceptor.replace(address(0xf1b38e), exitRegistrationStub);
    new NativeFunction(address(0x433450), 'void', [], 'mscdecl')();
    new NativeFunction(address(0x433520), 'void', [], 'mscdecl')();

    const heap = new NativeFunction(Module.getExportByName('kernel32.dll', 'GetProcessHeap'),
        'pointer', [], 'stdcall')();
    const allocate = new NativeFunction(Module.getExportByName('kernel32.dll', 'HeapAlloc'),
        'pointer', ['pointer', 'uint', 'uint'], 'stdcall');
    const release = new NativeFunction(Module.getExportByName('kernel32.dll', 'HeapFree'),
        'bool', ['pointer', 'uint', 'pointer'], 'stdcall');
    const buffers = new Map();
    function buffer(name, size) {
        const previous = buffers.get(name);
        if (previous !== undefined && previous.size >= size) return previous.pointer;
        const pointer = allocate(heap, 8, Math.max(size, 1));
        if (pointer.isNull()) throw new Error('HeapAlloc failed');
        if (previous !== undefined) release(heap, 0, previous.pointer);
        buffers.set(name, { pointer, size });
        return pointer;
    }

    const object = buffer('object', 0x1000);
    new NativeFunction(address(0x78ac80), 'pointer', ['pointer'], 'thiscall')(object);
    const callbacks = new Map();
    const sentinel = address(0x14ff84c).readPointer();
    let node = sentinel.readPointer();
    for (let count = 0; !node.equals(sentinel); count++) {
        if (count >= 32) throw new Error('Invalid cipher registry');
        callbacks.set(node.add(8).readU16(), new NativeFunction(node.add(12).readPointer(),
            'bool', ['pointer', 'uint', 'pointer', 'pointer', 'pointer', 'pointer',
                'uint', 'pointer', 'uint'], 'mscdecl'));
        node = node.readPointer();
    }
    const keys = new Map();
    for (const record of archiveKeys) {
        if (!Number.isInteger(record.id) || record.id <= 0 || record.id > 0xffff ||
            record.bytes.length !== 60 || keys.has(record.id))
            throw new Error('Invalid archive key record');
        keys.set(record.id, record.bytes);
    }
    nativeDecoder = {
        object, callbacks, buffer, keys,
        hash: new NativeFunction(address(0x791030), 'pointer',
            ['pointer', 'pointer', 'uint'], 'mscdecl'),
        header: new NativeFunction(address(0x78c800), 'bool',
            ['pointer', 'pointer', 'pointer', 'uint', 'pointer'], 'thiscall'),
        lz4: new NativeFunction(address(0x6ca320), 'int',
            ['pointer', 'uint', 'pointer', 'uint'], 'mscdecl'),
        zlib: new NativeFunction(address(0x6ca350), 'int',
            ['pointer', 'uint', 'pointer', 'uint'], 'mscdecl'),
    };
    const mode = object.add(0xe0).readPointer();
    return {
        cipherIds: Array.from(callbacks.keys()).sort((a, b) => a - b),
        archiveKeyIds: Array.from(keys.keys()).sort((a, b) => a - b),
        masterKeys: Array.from(new Uint8Array(object.add(0x40).readByteArray(128))),
        header71ModeVtable: mode.readPointer().toString(),
        header71CipherVtable: mode.add(4).readPointer().readPointer().toString(),
    };
};

rpc.exports.decodeEntry = function (name, expectedSize, payload) {
    if (nativeDecoder === null) throw new Error('Decoder is not initialized');
    const d = nativeDecoder;
    const inputSize = payload.byteLength;
    if (inputSize < 104) throw new Error('Truncated protected header');
    const path = d.buffer('name', name.length + 1);
    path.writeByteArray(name.concat([0]));
    const input = d.buffer('input', inputSize);
    input.writeByteArray(payload);
    const nameHash = d.buffer('nameHash', 16);
    d.hash(nameHash, path, name.length);
    const header = d.buffer('header', 104);
    if (!d.header(d.object, nameHash, input, inputSize, header))
        throw new Error('Protected header checksum failed');
    const cipherId = header.add(8).readU16();
    const compression = header.add(10).readU8();
    const paddedSize = header.add(12).readU32();
    const compressedSize = header.add(16).readU32();
    const outputSize = header.add(20).readU32();
    if (outputSize !== expectedSize || paddedSize > inputSize - 104 ||
        compressedSize > paddedSize)
        throw new Error('Unsupported or inconsistent entry sizes');
    const callback = d.callbacks.get(cipherId);
    if (callback === undefined) throw new Error('Unknown body cipher ' + cipherId);
    const parameters = d.buffer('parameters', 64);
    const keyId = header.add(40).readU32();
    const parameterFlags = header.add(11).readU8();
    if (parameterFlags & ~1) throw new Error('Unsupported parameter flags ' + parameterFlags);
    let material;
    if (keyId === 0) material = Array.from(new Uint8Array(header.add(44).readByteArray(60)));
    else {
        const record = d.keys.get(keyId);
        if (record === undefined) throw new Error('Missing archive key ' + keyId);
        material = record.slice();
    }
    if (parameterFlags & 1) {
        const hash = new Uint8Array(header.add(24).readByteArray(16));
        material = material.map((value, index) => value ^ hash[index % 16]);
    }
    parameters.writeByteArray(material);
    parameters.add(60).writeU32(0);
    const compressed = d.buffer('compressed', paddedSize);
    Memory.copy(compressed, input.add(104), Math.min(128, paddedSize));
    const skip = 128;
    // Padding alone does not create a compressed tail. In particular, never
    // subtract 128 from a shorter length and pass it to an unsigned native argument.
    if (compressedSize > skip && !callback(path, name.length, nameHash, parameters, header,
        input.add(104 + skip), paddedSize - skip, compressed.add(skip), compressedSize - skip))
        throw new Error('Body decoder failed for cipher ' + cipherId);
    const output = d.buffer('output', outputSize);
    let written;
    if (compression === 2) written = d.lz4(compressed, compressedSize, output, outputSize);
    else if (compression === 1) written = d.zlib(compressed, compressedSize, output, outputSize);
    else if (compression === 0 && compressedSize === outputSize) {
        Memory.copy(output, compressed, outputSize);
        written = outputSize;
    } else throw new Error('Unsupported compression ' + compression);
    if (written !== outputSize) throw new Error('Decompressed size mismatch');
    const digest = d.buffer('digest', 16);
    d.hash(digest, output, outputSize);
    const actual = new Uint8Array(digest.readByteArray(16));
    const expected = new Uint8Array(header.add(24).readByteArray(16));
    if (!actual.every((value, index) => value === expected[index]))
        throw new Error('Decompressed content checksum failed');
    send({ event: 'entry', cipherId, compression, headerType: input.add(1).readU8() });
    return output.readByteArray(outputSize);
};
