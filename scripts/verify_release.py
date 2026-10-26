#!/usr/bin/env python3
"""Verify the native release contents and exercise the TUI through a PTY."""
import argparse
import errno
import fcntl
import hashlib
import os
import pty
import re
import select
import shutil
import signal
import struct
import subprocess
import tarfile
import tempfile
import termios
import time
from pathlib import Path, PurePosixPath


ANSI = re.compile(rb'\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07\x1b]*(?:\x07|\x1b\\))')


def unpack(archive, destination):
    checksum = archive.with_suffix(archive.suffix + '.sha256').read_text().split()
    with archive.open('rb') as stream:
        actual = hashlib.file_digest(stream, 'sha256').hexdigest()
    if checksum != [actual, archive.name]:
        raise ValueError(f'checksum mismatch: {archive}')
    with tarfile.open(archive, 'r:gz') as package:
        members = package.getmembers()
        roots = set()
        for member in members:
            path = PurePosixPath(member.name)
            if path.is_absolute() or '..' in path.parts or not path.parts:
                raise ValueError(f'unsafe archive path: {member.name}')
            roots.add(path.parts[0])
            if not (member.isfile() or member.isdir() or member.issym() or member.islnk()):
                raise ValueError(f'unsupported archive member: {member.name}')
        if len(roots) != 1:
            raise ValueError('release archive must have exactly one root directory')
        package.extractall(destination, filter='data')
    release = (destination / roots.pop()).resolve()
    allowed = {'zero', 'README.md', 'docs'}
    if not {path.name for path in release.iterdir()} <= allowed:
        raise ValueError('release contains unexpected top-level files')
    for relative in ('zero', 'README.md', 'docs/tui.md'):
        if not (release / relative).is_file():
            raise ValueError(f'missing release file: {relative}')
    if not os.access(release / 'zero', os.X_OK):
        raise ValueError('zero must be executable')
    return release


def smoke_tui(command, cwd, env, timeout):
    master, slave = pty.openpty()
    fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack('HHHH', 40, 140, 0, 0))
    original_attrs = termios.tcgetattr(slave)
    output = bytearray()
    process = None
    ready = False
    quit_at = None
    try:
        process = subprocess.Popen([command], cwd=cwd, env=env, stdin=slave,
                                   stdout=slave, stderr=slave, start_new_session=True)
        os.close(slave)
        slave = None
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            readable, _, _ = select.select([master], [], [], 0.1)
            if readable:
                try:
                    chunk = os.read(master, 65536)
                except OSError as error:
                    if error.errno != errno.EIO:
                        raise
                    break
                if not chunk:
                    break
                output.extend(chunk)
                plain = ANSI.sub(b'', bytes(output))
                # These labels identify the native resource-library frame.
                if not ready and '资源库'.encode() in plain and '镜像'.encode() in plain:
                    ready = True
                    # Let the first native frame finish before sending input.
                    quit_at = time.monotonic() + 0.5
            if quit_at is not None and time.monotonic() >= quit_at:
                os.write(master, b'q')
                quit_at = None
                deadline = time.monotonic() + timeout
            if process.poll() is not None:
                break
        if process.poll() is None:
            try:
                process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                raise ValueError(f'TUI {"quit" if ready else "startup"} timed out') from None
        restored_attrs = termios.tcgetattr(master)
        mask = termios.ECHO | termios.ICANON | termios.ISIG
        if (restored_attrs[3] & mask) != (original_attrs[3] & mask):
            raise ValueError('terminal flags were not restored')
        if b'\x1b[?1049l' not in output or b'\x1b[?25h' not in output:
            raise ValueError('alternate screen or cursor was not restored')
        if not ready or process.returncode != 0:
            raise ValueError(f'TUI readiness={ready}, exit={process.returncode}')
    except (OSError, ValueError) as error:
        transcript = ANSI.sub(b'', bytes(output)).decode('utf-8', errors='replace')[-12000:]
        raise ValueError(f'{error}\nTUI transcript:\n{transcript}') from error
    finally:
        if process is not None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
        os.close(master)
        if slave is not None:
            os.close(slave)


def verify(archive, timeout):
    with tempfile.TemporaryDirectory(prefix='zero-release-smoke-') as temporary:
        temporary = Path(temporary)
        extracted = temporary / 'extracted'
        extracted.mkdir()
        release = unpack(archive, extracted)
        empty_path = temporary / 'empty-path'
        empty_path.mkdir()
        home = temporary / 'home'
        home.mkdir()
        # An allowlist also removes NODE_OPTIONS/NODE_PATH, ZERO_TUI_DIR,
        # ZERO_TUI_BACKEND and loader overrides that could mask packaging bugs.
        env = {'PATH': str(empty_path), 'HOME': str(home), 'TERM': 'xterm-256color',
               'COLORTERM': 'truecolor', 'LANG': 'C.UTF-8', 'TMPDIR': str(temporary),
               'XDG_CONFIG_HOME': str(home / 'config'), 'XDG_CACHE_HOME': str(home / 'cache'),
               'XDG_DATA_HOME': str(home / 'data')}
        if shutil.which('node', path=env['PATH']) or shutil.which('npm', path=env['PATH']):
            raise ValueError('smoke PATH unexpectedly contains Node/npm')
        help_text = subprocess.check_output(['./zero', '--help'], cwd=release,
                                            env=env, text=True, timeout=timeout)
        if 'zero' not in help_text.lower():
            raise ValueError('unexpected zero --help output')
        subprocess.run(['./zero', 'mcp', '--help'], cwd=release, env=env,
                       check=True, stdout=subprocess.DEVNULL, timeout=timeout)
        smoke_tui('./zero', release, env, timeout)
        work = temporary / 'unrelated-workdir'
        work.mkdir()
        smoke_tui(str(release / 'zero'), work, env, timeout)
        print(f'{archive.name}: native TUI ready + q exit (release and unrelated cwd; empty PATH)')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('archives', type=Path, nargs='+')
    parser.add_argument('--timeout', type=float, default=30)
    args = parser.parse_args()
    try:
        for archive in args.archives:
            verify(archive.resolve(strict=True), args.timeout)
    except (ValueError, OSError, subprocess.SubprocessError, tarfile.TarError) as error:
        parser.error(str(error))


if __name__ == '__main__':
    main()
