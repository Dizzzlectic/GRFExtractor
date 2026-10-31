// Exact-profile validation oracle, appended to the existing native decoder.
// Observes only one archive-key loader call at a time while the game stays at OEP.
let keyProbe = null;
let keyProbeCallback = null;
let keyProbeHandle = null;
let keyProbeThread = null;
let keyProbeFrame = null;
let keyProbeBuffer = null;
let keyProbeActive = false;
let keyProbeTrace = false;
let keyProbeSize = 0;
let keyProbeEvents = [];
let keyProbeHits = 0;
let keyProbeSequence = 0;

function keyProbeHex(pointer, length) {
    return Array.from(new Uint8Array(pointer.readByteArray(length)))
        .map(value => value.toString(16).padStart(2, '0')).join('');
}

rpc.exports.setupKeyProbe = function (trace) {
    keyProbeTrace = trace;
    if (!trace) return;
    const module = Process.getModuleByName('Ragexe.exe');
    Interceptor.attach(module.base.add(0x78d510 - 0x400000), {
        onEnter() {
            this.captureFrame = keyProbeActive && this.threadId === keyProbeThread.id;
            if (this.captureFrame) keyProbeFrame = ptr(this.context.esp.toString()).sub(4);
        },
        onLeave() { if (this.captureFrame) keyProbeFrame = null; },
    });
    Interceptor.attach(Module.getExportByName('ntdll.dll', 'RtlAllocateHeap'), {
        onEnter(args) {
            this.capture = keyProbeActive && this.threadId === keyProbeThread.id &&
                keyProbeFrame !== null && args[2].toUInt32() === keyProbeSize;
        },
        onLeave(result) {
            if (!this.capture || result.isNull()) return;
            // InvocationReturnValue is recycled after this callback.
            keyProbeBuffer = ptr(result.toString());
            try {
                keyProbeThread.setHardwareWatchpoint(0, keyProbeBuffer.add(keyProbeSize - 1), 1, 'w');
            } catch (error) {
                keyProbe.error = 'Hardware watchpoint failed: ' + error;
            }
        },
    });
    Process.setExceptionHandler(event => {
        if (!keyProbeActive || keyProbeBuffer === null ||
            Process.getCurrentThreadId() !== keyProbeThread.id ||
            !['breakpoint', 'single-step'].includes(event.type)) return false;
        keyProbeThread.unsetHardwareWatchpoint(0);
        keyProbeHits++;
        const body = new Uint8Array(keyProbeBuffer.readByteArray(keyProbeSize));
        if (body.some(value => value !== 0) && keyProbeFrame !== null) {
            const seed = Array.from(new Uint8Array(keyProbeFrame.sub(0x42c).readByteArray(16)));
            keyProbeEvents.push({
                digest: keyProbeHex(keyProbeFrame.sub(0x49c), 32),
                keySchedule: keyProbeHex(keyProbeFrame.sub(0x40c), 32),
                seed: seed.every(value => value >= 32 && value < 127)
                    ? String.fromCharCode(...seed) : null,
            });
        }
        if (keyProbeHits < 8)
            keyProbeThread.setHardwareWatchpoint(0, keyProbeBuffer.add(keyProbeSize - 1), 1, 'w');
        return true;
    });
};

rpc.exports.startKeyProbe = function (raw) {
    if (keyProbe !== null && !keyProbe.done) throw new Error('Key probe is busy');
    if (raw.length < 84 || (raw.length - 20) % 64 !== 0 || raw.length > 20 + 65535 * 64)
        throw new Error('Expected a bounded complete archive-key block');
    keyProbe = { done: false };
    keyProbeEvents = [];
    keyProbeHits = 0;
    keyProbeSize = raw.length - 20;
    keyProbeCallback = new NativeCallback(() => {
        try {
            keyProbeThread = Process.enumerateThreads().find(thread => thread.id === Process.getCurrentThreadId());
            if (keyProbeTrace && keyProbeThread === undefined)
                throw new Error('Observation thread is unavailable to the Thread API');
            const module = Process.getModuleByName('Ragexe.exe');
            const address = va => module.base.add(va - 0x400000);
            const object = nativeDecoder.buffer('key-probe-object-' + keyProbeSequence++, 4096);
            // A fresh zeroed context prevents records from a previous call surviving.
            object.writeByteArray(new Uint8Array(4096));
            new NativeFunction(address(0x78ac80), 'pointer', ['pointer'], 'thiscall')(object);
            const blob = nativeDecoder.buffer('key-probe-blob', raw.length);
            blob.writeByteArray(raw);
            const empty = nativeDecoder.buffer('key-probe-empty', 1);
            empty.writeU8(0);
            const load = new NativeFunction(address(0x78d510), 'uint',
                ['pointer', 'pointer', 'uint', 'pointer', 'uint'],
                { abi: 'thiscall', exceptions: keyProbeTrace ? 'propagate' : 'steal' });
            keyProbeActive = true;
            const status = load(object, empty, 0, blob, raw.length) & 255;
            keyProbe.value = { accepted: status === 1, status, records: object.add(8).readU32(),
                parameter_samples: keyProbeEvents };
        } catch (error) {
            keyProbe.error = String(error);
        } finally {
            if (keyProbeTrace && keyProbeBuffer !== null) {
                try { keyProbeThread.unsetHardwareWatchpoint(0); } catch (_) {}
            }
            keyProbeActive = false;
            keyProbeBuffer = null;
            keyProbeThread = null;
            keyProbe.done = true;
        }
        return 0;
    }, 'uint', ['pointer'], 'stdcall');
    const create = new NativeFunction(Module.getExportByName('kernel32.dll', 'CreateThread'),
        'pointer', ['pointer', 'uint', 'pointer', 'pointer', 'uint', 'pointer'], 'stdcall');
    keyProbeHandle = create(ptr(0), 0, keyProbeCallback, ptr(0), 0, ptr(0));
    if (keyProbeHandle.isNull()) throw new Error('Could not create observation thread');
};

rpc.exports.pollKeyProbe = function () {
    if (keyProbe.done && keyProbeHandle !== null) {
        new NativeFunction(Module.getExportByName('kernel32.dll', 'CloseHandle'),
            'bool', ['pointer'], 'stdcall')(keyProbeHandle);
        keyProbeHandle = null;
    }
    return keyProbe;
};
