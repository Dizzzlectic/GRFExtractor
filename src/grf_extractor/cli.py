"""Resumable, collision-safe extraction with portable or exact-build native decoding."""

import argparse
import collections
import fnmatch
import hashlib
import json
import os
from pathlib import Path
import time

from grfkit.archive import Archive
from grfkit.cli import MANIFEST, metadata, portable_paths, record
from .native.decoder import NativeDecoder, load_profile
from .output import sha256, write_atomic

CHECKPOINT_ENTRIES = 10000
CHECKPOINT_SECONDS = 60
CHECKPOINT_SCHEMA = 'grf-extractor-checkpoint-2'


def probe_entries(archive, entries):
    groups = collections.defaultdict(list)
    for entry in entries:
        if entry.protected:
            archive.handle.seek(46 + entry.offset)
            groups[archive.handle.read(4)].append(entry)
    chosen = {}
    for group in groups.values():
        ordered = sorted(group, key=lambda entry: entry.aligned_size)
        for entry in ordered[:3] + [ordered[i * (len(ordered) - 1) // 11] for i in range(12)]:
            chosen[entry.index] = entry
    for entry in entries:
        if entry.raw_name.lower().replace(b'\\', b'/') in {
            b'data/msgstringtable.csv', b'data/cardprefixnametable.txt',
            b'data/luafiles514/lua files/skillinfoz/skillinfolist.lub',
        }:
            chosen[entry.index] = entry
    return list(chosen.values())


def target_path(root, relative):
    """Reject symlinks at every existing component, including the extraction root."""
    target = root
    if root.is_symlink():
        raise ValueError('symlink extraction root')
    for part in relative.split('/'):
        if part in ('', '.', '..') or '\\' in part or ':' in part:
            raise ValueError('unsafe extraction path')
        target /= part
        if target.is_symlink():
            raise ValueError('symlink extraction path')
    return target


def main(argv=None, *, checkpoint_enabled=True):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--client', type=Path, help='Isolated Ragexe.exe copy (native mode)')
    parser.add_argument('--archive', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True, help='New extraction directory')
    parser.add_argument('--unlicense-agent', type=Path, help='Pinned Frida startup agent (native mode)')
    parser.add_argument('--portable', action='store_true', help='Use portable decoding (the default without native inputs)')
    parser.add_argument('--probe', action='store_true', help='Only representative protected entries')
    parser.add_argument('--entry', action='append', help='Extract only a named entry; repeat as needed')
    parser.add_argument('--match', action='append', help='Case-insensitive path glob; repeat as needed')
    parser.add_argument('--resume', action='store_true', help='Recover unfinished records from a versioned checkpoint')
    parser.add_argument('--repair-known-wav', action='store_true')
    args = parser.parse_args(argv)
    checkpoint_enabled = checkpoint_enabled or args.resume
    mode = 'native' if not args.portable and (args.client or args.unlicense_agent) else 'portable'
    profile = None
    if mode == 'native':
        if args.client is None or args.unlicense_agent is None:
            parser.error('Native mode requires --client and --unlicense-agent')
        profile = load_profile()
        if os.name != 'nt':
            parser.error('Use Windows Python for the native decoder, or select --portable')
        if args.client.name != 'Ragexe.exe' or sha256(args.client) != profile['sha256']:
            parser.error('Executable does not match the supported client profile')
        if args.client.parent.resolve() == args.archive.parent.resolve():
            parser.error('Client must be an isolated copy outside the original client directory')
    if args.output.is_symlink() or (args.output.exists() and not args.resume):
        parser.error('Output directory already exists or is a symlink; choose a new directory')
    checkpoint_path = args.output.with_name(args.output.name + '.manifest.json')
    if checkpoint_enabled and (checkpoint_path.is_symlink() or (checkpoint_path.exists() and not args.resume)):
        parser.error('Output manifest already exists or is a symlink; choose a new output')
    try:
        with Archive(args.archive) as archive:
            return extract(args, archive, parser, checkpoint_path, checkpoint_enabled, mode, profile)
    except (OSError, ValueError) as error:
        parser.error(str(error))


def extract(args, archive, parser, checkpoint_path, checkpoint_enabled, mode, profile):
    entries = [entry for entry in archive.entries if entry.is_file]
    all_entry_count = len(entries)
    protected_entry_count = sum(entry.protected for entry in entries)
    if args.entry:
        requested = {name.lower().replace('\\', '/') for name in args.entry}
        found = {entry.name.lower() for entry in entries}
        if requested - found:
            parser.error('One or more requested entries were not found')
        entries = [entry for entry in entries if entry.name.lower() in requested]
    if args.match:
        entries = [entry for entry in entries if any(fnmatch.fnmatchcase(
            entry.name.casefold(), pattern.replace('\\', '/').casefold()) for pattern in args.match)]
    if args.probe:
        entries = probe_entries(archive, entries)
    paths = portable_paths(entries)
    selected_entries = list(entries)
    by_path = {paths[entry.index]: entry for entry in entries}
    # Validate the entire selection before making the extraction directory.
    for relative in paths.values():
        target_path(args.output, relative)
    manifest = {
        'schema': CHECKPOINT_SCHEMA,
        'archive': args.archive.name,
        'archive_size': args.archive.stat().st_size,
        'archive_mtime_ns': args.archive.stat().st_mtime_ns,
        'archive_sha256': sha256(args.archive) if checkpoint_enabled else None,
        'client_sha256': profile['sha256'] if profile else None,
        'decoder_mode': mode, 'probe': args.probe, 'selection': args.entry, 'match': args.match,
        'entries': len(entries), 'extracted': 0, 'failures': [], 'files': {}, 'repairs': [],
    }
    if args.resume:
        try:
            previous = json.loads(checkpoint_path.read_text(encoding='utf-8'))
            if not isinstance(previous, dict) or previous.get('schema') != CHECKPOINT_SCHEMA:
                parser.error('Resume schema differs; use a fresh extraction for legacy or unknown checkpoints')
            for field in ('archive', 'archive_size', 'archive_mtime_ns', 'archive_sha256',
                          'client_sha256', 'decoder_mode', 'probe', 'selection', 'match', 'entries'):
                if previous.get(field) != manifest[field]:
                    parser.error(f'Resume source or selection mismatch: {field}')
            if not isinstance(previous.get('files'), dict) or previous.get('extracted') != len(previous['files']):
                parser.error('Resume manifest success count mismatch')
            for relative, row in previous['files'].items():
                try:
                    entry = by_path[relative]
                    target = target_path(args.output, relative)
                    valid = (row['index'] == entry.index and row['raw_name'] == entry.raw_name.hex()
                             and row['size'] == entry.real_size and row['flags'] == entry.flags
                             and target.is_file() and target.stat().st_size == row['size']
                             and sha256(target) == row['sha256'])
                except (OSError, ValueError, KeyError, TypeError):
                    valid = False
                if not valid:
                    parser.error(f'Resume recorded output is missing, modified or unsafe: {relative}')
            entries = [entry for entry in entries if paths[entry.index] not in previous['files']]
            manifest = previous
            manifest['failures'] = []
        except (OSError, ValueError, TypeError) as error:
            parser.error(f'Cannot read resume manifest: {error}')
    decoder = None
    failures = {}
    previous_formats = collections.Counter({(item['header'], item['cipher'], item['compression']): item['count']
                        for item in manifest.get('protected_formats', [])})

    def checkpoint():
        rows = []
        for entry in selected_entries:
            relative = paths[entry.index]
            if relative in manifest['files']:
                rows.append(dict(manifest['files'][relative], path=relative))
            else:
                rows.append(record(entry, path=relative,
                    error=failures.get(entry.index, 'Not processed: extraction interrupted')))
        # The pack manifest is always present, and incomplete extractions refuse packing.
        raw = [metadata(archive)] + rows
        write_atomic(args.output / MANIFEST,
                     ''.join(json.dumps(row, ensure_ascii=True) + '\n' for row in raw).encode(), replace=True)
        if not checkpoint_enabled:
            return
        snapshot = dict(manifest)
        snapshot['extracted'] = len(manifest['files'])
        snapshot['failures'] = [row for row in rows if 'error' in row]
        counts = previous_formats.copy()
        if decoder is not None:
            counts.update(decoder.metadata_counts)
        snapshot['protected_formats'] = [dict(header=k[0], cipher=k[1], compression=k[2], count=v)
                                         for k, v in sorted(counts.items())]
        whole = not args.probe and not args.entry and not args.match
        snapshot['complete'] = whole and len(manifest['files']) == all_entry_count and not snapshot['failures']
        snapshot['lossless_complete'] = snapshot['complete'] and not manifest['repairs']
        snapshot['protected_entries'] = protected_entry_count
        snapshot['protected_extracted'] = sum(row['flags'] == 128 for row in manifest['files'].values())
        snapshot['protected_complete'] = whole and snapshot['protected_extracted'] == protected_entry_count
        write_atomic(checkpoint_path, (json.dumps(snapshot, ensure_ascii=True, indent=2) + '\n').encode(), replace=True)

    args.output.mkdir(parents=True, exist_ok=args.resume)
    checkpoint()
    started = last_checkpoint = time.monotonic()
    try:
        if mode == 'native':
            decoder = NativeDecoder(args.client, args.unlicense_agent, profile, archive.keys)
        else:
            from .codecs.decoder import PortableDecoder
            decoder = PortableDecoder(archive.keys)
        for index, entry in enumerate(entries, 1):
            try:
                relative = paths[entry.index]
                target = target_path(args.output, relative)
                # Both workflows use the same ordinary decoder/repair. Native mode only
                # substitutes the protected body oracle, with its exact client profile.
                if entry.protected:
                    payload = archive.payload(entry)
                    if mode == 'portable':
                        payload = payload[:entry.compressed_size]
                    data = decoder.decode(entry.raw_name, entry.real_size, payload)
                else:
                    data = archive.read(entry, repair_known_wav=args.repair_known_wav)
                if len(data) != entry.real_size:
                    raise ValueError('Extracted size mismatch')
                fixed = entry.index in archive.repaired_indices
                digest = hashlib.sha256(data).hexdigest()
                target.parent.mkdir(parents=True, exist_ok=True)
                if args.resume and target.exists():
                    if not target.is_file() or target.stat().st_size != len(data) or sha256(target) != digest:
                        raise ValueError('Resume target exists and differs from freshly decoded content')
                else:
                    write_atomic(target, data)
                manifest['files'][relative] = record(entry, data, repaired=fixed)
                if fixed:
                    manifest['repairs'].append({'path': relative, 'repair': 'known-wav-seven-zero-bytes'})
                manifest['extracted'] = len(manifest['files'])
            except Exception as error:
                failures[entry.index] = str(error).splitlines()[0]
                print('Failed:', entry.raw_name, failures[entry.index], flush=True)
            if index % CHECKPOINT_ENTRIES == 0 or time.monotonic() - last_checkpoint >= CHECKPOINT_SECONDS:
                checkpoint()
                last_checkpoint = time.monotonic()
            if index % 1000 == 0 or index == len(entries):
                print(f"{index}/{len(entries)}: {len(manifest['files'])} extracted, {len(failures)} failed", flush=True)
    finally:
        try:
            checkpoint()
        finally:
            if decoder is not None:
                decoder.close()
    return int(bool(failures) or len(manifest['files']) != len(selected_entries))
