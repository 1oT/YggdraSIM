# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""Small, dependency-free helpers for private runtime files.

The helpers in this module deliberately avoid following a final-path symlink
and make the requested POSIX permissions true even when the process inherited
a permissive umask.  On Windows they replace inherited access-control entries
with a protected DACL granting full access only to the current user, Local
System, and built-in Administrators.
"""
from __future__ import annotations

import ctypes
import errno
import os
import stat
import tempfile
from pathlib import Path
from typing import Union


Pathish = Union[str, os.PathLike[str]]
PRIVATE_DIRECTORY_MODE = 0o700
PRIVATE_FILE_MODE = 0o600


def _path(value: Pathish) -> Path:
    text = os.fspath(value)
    if not text:
        raise ValueError("path must not be empty")
    return Path(text).expanduser().absolute()


def _reject_final_symlink(path: Path) -> None:
    try:
        info = path.lstat()
    except FileNotFoundError:
        return
    reparse_flag = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
    file_attributes = int(getattr(info, "st_file_attributes", 0))
    if stat.S_ISLNK(info.st_mode) or bool(file_attributes & reparse_flag):
        raise OSError(
            errno.ELOOP,
            "refusing to use a symbolic link or reparse point",
            str(path),
        )


def _chmod_private(path: Path, mode: int) -> None:
    """Apply *mode* without dereferencing a final symlink."""
    _reject_final_symlink(path)
    try:
        os.chmod(path, mode, follow_symlinks=False)
    except (NotImplementedError, TypeError):
        # Windows and a few older Unix Python builds do not implement the
        # follow_symlinks keyword.  The lstat immediately above still prevents
        # the normal accidental-link case.
        os.chmod(path, mode)
    if os.name == "nt":
        _set_private_windows_dacl(path)


def _set_private_windows_dacl(path: Path) -> None:
    """Apply a protected user/System/Administrators-only Windows DACL."""
    from ctypes import wintypes

    if not hasattr(ctypes, "windll"):
        raise PermissionError("Windows DACL authoring is unavailable")
    advapi32 = ctypes.windll.advapi32
    kernel32 = ctypes.windll.kernel32

    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    kernel32.LocalFree.restype = ctypes.c_void_p
    advapi32.OpenProcessToken.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.HANDLE),
    ]
    advapi32.OpenProcessToken.restype = wintypes.BOOL
    advapi32.GetTokenInformation.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    ]
    advapi32.GetTokenInformation.restype = wintypes.BOOL
    advapi32.ConvertSidToStringSidW.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(wintypes.LPWSTR),
    ]
    advapi32.ConvertSidToStringSidW.restype = wintypes.BOOL
    advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
        wintypes.LPWSTR,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(wintypes.DWORD),
    ]
    advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = (
        wintypes.BOOL
    )
    advapi32.GetSecurityDescriptorDacl.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(wintypes.BOOL),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(wintypes.BOOL),
    ]
    advapi32.GetSecurityDescriptorDacl.restype = wintypes.BOOL
    advapi32.SetNamedSecurityInfoW.argtypes = [
        wintypes.LPWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
    ]
    advapi32.SetNamedSecurityInfoW.restype = wintypes.DWORD

    token = wintypes.HANDLE()
    if not advapi32.OpenProcessToken(
        kernel32.GetCurrentProcess(),
        0x0008,  # TOKEN_QUERY
        ctypes.byref(token),
    ):
        raise PermissionError("could not query the current Windows token")
    try:
        required = wintypes.DWORD()
        advapi32.GetTokenInformation(
            token,
            1,  # TokenUser
            None,
            0,
            ctypes.byref(required),
        )
        if required.value == 0:
            raise PermissionError("could not size the current Windows user token")
        token_buffer = ctypes.create_string_buffer(required.value)
        if not advapi32.GetTokenInformation(
            token,
            1,
            token_buffer,
            required.value,
            ctypes.byref(required),
        ):
            raise PermissionError("could not resolve the current Windows user SID")

        class _SidAndAttributes(ctypes.Structure):
            _fields_ = [
                ("Sid", ctypes.c_void_p),
                ("Attributes", wintypes.DWORD),
            ]

        class _TokenUser(ctypes.Structure):
            _fields_ = [("User", _SidAndAttributes)]

        token_user = ctypes.cast(token_buffer, ctypes.POINTER(_TokenUser)).contents
        sid_text_pointer = wintypes.LPWSTR()
        if not advapi32.ConvertSidToStringSidW(
            token_user.User.Sid,
            ctypes.byref(sid_text_pointer),
        ):
            raise PermissionError("could not encode the current Windows user SID")
        try:
            sid_text = str(sid_text_pointer.value or "")
        finally:
            kernel32.LocalFree(ctypes.cast(sid_text_pointer, ctypes.c_void_p))
    finally:
        kernel32.CloseHandle(token)

    if not sid_text:
        raise PermissionError("current Windows user SID is unavailable")
    sddl = (
        "D:P"
        "(A;;FA;;;SY)"
        "(A;;FA;;;BA)"
        f"(A;;FA;;;{sid_text})"
    )
    descriptor = ctypes.c_void_p()
    if not advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW(
        wintypes.LPWSTR(sddl),
        1,  # SDDL_REVISION_1
        ctypes.byref(descriptor),
        None,
    ):
        raise PermissionError("could not construct a private Windows DACL")
    try:
        dacl_present = wintypes.BOOL()
        dacl_defaulted = wintypes.BOOL()
        dacl = ctypes.c_void_p()
        if not advapi32.GetSecurityDescriptorDacl(
            descriptor,
            ctypes.byref(dacl_present),
            ctypes.byref(dacl),
            ctypes.byref(dacl_defaulted),
        ):
            raise PermissionError("could not extract the private Windows DACL")
        if not dacl_present or not dacl.value:
            raise PermissionError("constructed Windows DACL is unavailable")
        status_code = advapi32.SetNamedSecurityInfoW(
            wintypes.LPWSTR(str(path)),
            1,  # SE_FILE_OBJECT
            0x00000004 | 0x80000000,  # DACL + PROTECTED_DACL
            None,
            None,
            dacl,
            None,
        )
        if status_code != 0:
            raise PermissionError(
                f"could not apply private Windows DACL (error {status_code})"
            )
    finally:
        kernel32.LocalFree(descriptor)


def ensure_private_directory(path: Pathish) -> Path:
    """Create or harden one private directory and return its absolute path."""
    target = _path(path)
    _reject_final_symlink(target)
    target.mkdir(mode=PRIVATE_DIRECTORY_MODE, parents=True, exist_ok=True)
    if not target.is_dir():
        raise NotADirectoryError(str(target))
    _chmod_private(target, PRIVATE_DIRECTORY_MODE)
    return target


def ensure_private_file(path: Pathish) -> Path:
    """Harden an existing regular file to user-only access."""
    target = _path(path)
    _reject_final_symlink(target)
    if not target.is_file():
        raise FileNotFoundError(str(target))
    _chmod_private(target, PRIVATE_FILE_MODE)
    return target


def assert_private_file(path: Pathish) -> Path:
    """Require a regular secret file owned/readable only by trusted principals.

    POSIX permits only the effective user.  Windows permits the current user,
    LocalSystem, and the built-in Administrators group; if the DACL cannot be
    inspected, the check fails closed instead of claiming confidentiality.
    """
    target = _path(path)
    _reject_final_symlink(target)
    info = target.stat()
    _assert_private_stat(info, target)
    if os.name == "nt":
        _assert_private_windows_dacl(target)
    return target


def _assert_private_stat(info: os.stat_result, target: Path) -> None:
    """Validate private-file properties available from an opened descriptor."""
    if not stat.S_ISREG(info.st_mode):
        raise PermissionError(f"secret path is not a regular file: {target}")
    if os.name == "nt":
        return
    if hasattr(os, "geteuid") and int(info.st_uid) != int(os.geteuid()):
        raise PermissionError(f"secret file is not owned by the current user: {target}")
    if stat.S_IMODE(info.st_mode) & 0o077:
        raise PermissionError(
            f"secret file permissions must not grant group/other access: {target}"
        )


def _assert_private_windows_dacl(path: Path) -> None:
    """Fail closed unless the Windows owner/DACL is user-private."""
    from ctypes import wintypes

    if not hasattr(ctypes, "windll"):
        raise PermissionError("Windows DACL inspection is unavailable")
    advapi32 = ctypes.windll.advapi32
    kernel32 = ctypes.windll.kernel32
    advapi32.GetNamedSecurityInfoW.argtypes = [
        wintypes.LPWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
    ]
    advapi32.GetNamedSecurityInfoW.restype = wintypes.DWORD
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    advapi32.OpenProcessToken.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.HANDLE),
    ]
    advapi32.OpenProcessToken.restype = wintypes.BOOL
    advapi32.GetTokenInformation.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    ]
    advapi32.GetTokenInformation.restype = wintypes.BOOL
    advapi32.EqualSid.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
    advapi32.EqualSid.restype = wintypes.BOOL
    advapi32.ConvertStringSidToSidW.argtypes = [
        wintypes.LPWSTR,
        ctypes.POINTER(ctypes.c_void_p),
    ]
    advapi32.ConvertStringSidToSidW.restype = wintypes.BOOL
    advapi32.GetAclInformation.argtypes = [
        ctypes.c_void_p,
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
    ]
    advapi32.GetAclInformation.restype = wintypes.BOOL
    advapi32.GetAce.argtypes = [
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p),
    ]
    advapi32.GetAce.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    kernel32.LocalFree.restype = ctypes.c_void_p

    owner_sid = ctypes.c_void_p()
    dacl = ctypes.c_void_p()
    descriptor = ctypes.c_void_p()
    status_code = advapi32.GetNamedSecurityInfoW(
        wintypes.LPWSTR(str(path)),
        1,  # SE_FILE_OBJECT
        0x00000001 | 0x00000004,  # OWNER + DACL
        ctypes.byref(owner_sid),
        None,
        ctypes.byref(dacl),
        None,
        ctypes.byref(descriptor),
    )
    if status_code != 0:
        raise PermissionError(
            f"could not inspect Windows DACL for secret file (error {status_code})"
        )
    try:
        if not owner_sid.value:
            raise PermissionError("secret file has no Windows owner SID")
        if not dacl.value:
            raise PermissionError("secret file has a NULL (unrestricted) Windows DACL")

        token = wintypes.HANDLE()
        if not advapi32.OpenProcessToken(
            kernel32.GetCurrentProcess(),
            0x0008,  # TOKEN_QUERY
            ctypes.byref(token),
        ):
            raise PermissionError("could not query the current Windows token")
        try:
            required = wintypes.DWORD()
            advapi32.GetTokenInformation(
                token,
                1,  # TokenUser
                None,
                0,
                ctypes.byref(required),
            )
            if required.value == 0:
                raise PermissionError("could not size the current Windows user token")
            token_buffer = ctypes.create_string_buffer(required.value)
            if not advapi32.GetTokenInformation(
                token,
                1,
                token_buffer,
                required.value,
                ctypes.byref(required),
            ):
                raise PermissionError("could not resolve the current Windows user SID")

            class _SidAndAttributes(ctypes.Structure):
                _fields_ = [
                    ("Sid", ctypes.c_void_p),
                    ("Attributes", wintypes.DWORD),
                ]

            class _TokenUser(ctypes.Structure):
                _fields_ = [("User", _SidAndAttributes)]

            token_user = ctypes.cast(
                token_buffer,
                ctypes.POINTER(_TokenUser),
            ).contents
            current_sid = ctypes.c_void_p(token_user.User.Sid)
            if not current_sid.value:
                raise PermissionError("current Windows user SID is unavailable")
            if not advapi32.EqualSid(owner_sid, current_sid):
                raise PermissionError(
                    "secret file is not owned by the current Windows user"
                )

            trusted_sids: list[ctypes.c_void_p] = [current_sid]
            allocated_sids: list[ctypes.c_void_p] = []
            for sid_text in ("S-1-5-18", "S-1-5-32-544"):
                sid_pointer = ctypes.c_void_p()
                if not advapi32.ConvertStringSidToSidW(
                    wintypes.LPWSTR(sid_text),
                    ctypes.byref(sid_pointer),
                ):
                    raise PermissionError("could not construct a trusted Windows SID")
                allocated_sids.append(sid_pointer)
                trusted_sids.append(sid_pointer)
            try:
                class _AclSizeInformation(ctypes.Structure):
                    _fields_ = [
                        ("AceCount", wintypes.DWORD),
                        ("AclBytesInUse", wintypes.DWORD),
                        ("AclBytesFree", wintypes.DWORD),
                    ]

                acl_info = _AclSizeInformation()
                if not advapi32.GetAclInformation(
                    dacl,
                    ctypes.byref(acl_info),
                    ctypes.sizeof(acl_info),
                    2,  # AclSizeInformation
                ):
                    raise PermissionError("could not inspect secret-file ACEs")
                for ace_index in range(int(acl_info.AceCount)):
                    ace = ctypes.c_void_p()
                    if not advapi32.GetAce(dacl, ace_index, ctypes.byref(ace)):
                        raise PermissionError("could not read a secret-file ACE")
                    ace_bytes = ctypes.string_at(ace, 8)
                    ace_type = ace_bytes[0]
                    if ace_type in {5, 9, 11}:
                        # Object/callback allow ACEs encode their SID at a
                        # variable offset.  Treat them as unsafe rather than
                        # accidentally overlooking a grant to another user.
                        raise PermissionError(
                            "secret file uses an unsupported Windows allow ACE"
                        )
                    if ace_type != 0:  # ACCESS_ALLOWED_ACE_TYPE
                        continue
                    ace_sid = ctypes.c_void_p(int(ace.value) + 8)
                    if not any(
                        bool(advapi32.EqualSid(ace_sid, trusted_sid))
                        for trusted_sid in trusted_sids
                    ):
                        raise PermissionError(
                            "secret file grants access to an untrusted Windows principal"
                        )
            finally:
                for sid_pointer in allocated_sids:
                    kernel32.LocalFree(sid_pointer)
        finally:
            kernel32.CloseHandle(token)
    finally:
        kernel32.LocalFree(descriptor)


def harden_private_tree(path: Pathish) -> Path:
    """Harden an existing data tree without following links.

    Symbolic links are rejected instead of traversed.  Runtime workspaces are
    data stores, so executable permission is intentionally removed from files.
    """
    root = ensure_private_directory(path)
    for current_root, directory_names, file_names in os.walk(
        root,
        topdown=True,
        followlinks=False,
    ):
        current = Path(current_root)
        safe_directories: list[str] = []
        for name in directory_names:
            candidate = current / name
            if candidate.is_symlink():
                raise OSError(
                    errno.ELOOP,
                    "private data trees must not contain symbolic links",
                    str(candidate),
                )
            ensure_private_directory(candidate)
            safe_directories.append(name)
        directory_names[:] = safe_directories
        for name in file_names:
            candidate = current / name
            if candidate.is_symlink():
                raise OSError(
                    errno.ELOOP,
                    "private data trees must not contain symbolic links",
                    str(candidate),
                )
            if candidate.is_file():
                ensure_private_file(candidate)
    return root


def _write_all(fd: int, payload: bytes) -> None:
    view = memoryview(payload)
    written = 0
    while written < len(view):
        count = os.write(fd, view[written:])
        if count <= 0:
            raise OSError(errno.EIO, "short write")
        written += count


def _read_bounded_open_file(
    path: Pathish,
    max_bytes: int,
    *,
    require_private: bool,
) -> bytes:
    """Read a stable snapshot while retaining the validated descriptor."""
    target = _path(path)
    limit = int(max_bytes)
    if limit < 0:
        raise ValueError("max_bytes must be non-negative")
    _reject_final_symlink(target)
    flags = os.O_RDONLY
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(target, flags)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode):
            raise OSError(errno.EINVAL, "path is not a regular file", str(target))
        if require_private:
            _assert_private_stat(before, target)
            if os.name == "nt":
                # Windows DACL inspection is path-based in the stdlib/ctypes
                # implementation.  Pin the file first, inspect its DACL, then
                # prove the path still names the opened object before reading.
                _assert_private_windows_dacl(target)
                named = target.stat()
                if (
                    int(named.st_dev),
                    int(named.st_ino),
                ) != (
                    int(before.st_dev),
                    int(before.st_ino),
                ):
                    raise OSError(
                        errno.EAGAIN,
                        "secret path changed while its ACL was inspected",
                        str(target),
                    )
        if int(before.st_size) > limit:
            raise ValueError(f"file exceeds the {limit}-byte limit")
        chunks: list[bytes] = []
        remaining = limit + 1
        while remaining > 0:
            chunk = os.read(fd, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        if len(payload) > limit:
            raise ValueError(f"file exceeds the {limit}-byte limit")
        after = os.fstat(fd)
        before_identity = (
            int(before.st_dev),
            int(before.st_ino),
            int(before.st_size),
            int(getattr(before, "st_mtime_ns", int(before.st_mtime * 1e9))),
        )
        after_identity = (
            int(after.st_dev),
            int(after.st_ino),
            int(after.st_size),
            int(getattr(after, "st_mtime_ns", int(after.st_mtime * 1e9))),
        )
        if before_identity != after_identity or len(payload) != int(after.st_size):
            raise OSError(
                errno.EAGAIN,
                "file changed while it was being read",
                str(target),
            )
        return payload
    finally:
        os.close(fd)


def read_bounded_regular_file(path: Pathish, max_bytes: int) -> bytes:
    """Read one stable regular-file snapshot without following the final link."""
    return _read_bounded_open_file(path, max_bytes, require_private=False)


def read_bounded_private_file(path: Pathish, max_bytes: int) -> bytes:
    """Read private bytes from the same descriptor whose metadata was checked.

    This is the appropriate helper for signing keys and other secrets.  It
    avoids the check/use race created by validating a pathname and opening it
    again later.
    """
    return _read_bounded_open_file(path, max_bytes, require_private=True)


def _fsync_directory(path: Path) -> None:
    if os.name != "posix":
        return
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    try:
        fd = os.open(path, flags)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


def atomic_write_bytes(
    path: Pathish,
    data: bytes,
    *,
    overwrite: bool = True,
    mode: int = PRIVATE_FILE_MODE,
) -> Path:
    """Publish *data* as one private file in the target directory.

    ``overwrite=False`` first reserves the destination with an exclusive
    create and verifies that reservation before the atomic replacement.  This
    gives portable no-overwrite behaviour without relying on hard links.
    """
    target = _path(path)
    parent = target.parent
    parent.mkdir(mode=PRIVATE_DIRECTORY_MODE, parents=True, exist_ok=True)
    _reject_final_symlink(target)

    temp_fd, temp_name = tempfile.mkstemp(
        prefix=f".{target.name}.",
        suffix=".tmp",
        dir=str(parent),
    )
    temp_path = Path(temp_name)
    reserved_identity: tuple[int, int] | None = None
    try:
        try:
            if hasattr(os, "fchmod"):
                os.fchmod(temp_fd, mode)
            _write_all(temp_fd, bytes(data))
            os.fsync(temp_fd)
        finally:
            os.close(temp_fd)

        if not overwrite:
            flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            reserve_fd = os.open(target, flags, mode)
            try:
                if hasattr(os, "fchmod"):
                    os.fchmod(reserve_fd, mode)
                reserved = os.fstat(reserve_fd)
                reserved_identity = (int(reserved.st_dev), int(reserved.st_ino))
            finally:
                os.close(reserve_fd)

            current = target.lstat()
            if reserved_identity != (int(current.st_dev), int(current.st_ino)):
                raise OSError(
                    errno.EAGAIN,
                    "destination changed during exclusive publication",
                    str(target),
                )

        os.replace(temp_path, target)
        _chmod_private(target, mode)
        _fsync_directory(parent)
        return target
    except Exception:
        try:
            temp_path.unlink()
        except FileNotFoundError:
            pass
        if reserved_identity is not None:
            try:
                current = target.lstat()
                if reserved_identity == (int(current.st_dev), int(current.st_ino)):
                    target.unlink()
            except FileNotFoundError:
                pass
        raise


__all__ = [
    "PRIVATE_DIRECTORY_MODE",
    "PRIVATE_FILE_MODE",
    "atomic_write_bytes",
    "assert_private_file",
    "ensure_private_directory",
    "ensure_private_file",
    "harden_private_tree",
    "read_bounded_private_file",
    "read_bounded_regular_file",
]
