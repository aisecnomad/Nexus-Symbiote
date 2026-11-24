"""Stage one digest-pinned launcher and stop it, including ``setsid`` descendants.

``live.stdio`` and ``live.session`` both copy the approved bytes and execute that
private copy. One helper keeps the copy, the digest check and the termination from
drifting apart. When the kernel allows a user and PID namespace, the launcher is
pid 1 of that namespace. It starts only once the caller holds a pidfd for it, and
cleanup kills it through that pidfd, or, where no pidfd can be held, as the child of a
stopped ``unshare``. Cleanup then waits until the kernel has ended every process in
the namespace, or reports that it could not. If the kernel refuses the namespace,
launch fails before executing the pinned program. On Linux,
``--no-isolation`` starts the launcher as the child of a short wrapper that stays alive
as a child subreaper, and cleanup stops the wrapper and sweeps its tree. A double-fork,
a ``clone(CLONE_PARENT)`` child that calls ``setsid``, and a descendant of a launcher
that already exited are all reparented to the wrapper, so they die with the session.
The wrapper ignores every signal it can and cannot be traced by its user's other
processes, and the launcher leads its own process group, so only a SIGKILL aimed at the
wrapper ends it early. Cleanup then reports ``isolation-teardown-failed``, because what
the wrapper had adopted may have left the tree, as it does when something below the
wrapper cannot be killed. An opted-out launch also joins a private cgroup v2 when the
current cgroup allows a child, and cleanup writes ``cgroup.kill``, and it signals every
process still in the wrapper's session; that cgroup, where one exists, still reaches
what a launcher that killed its wrapper started. Neither is a PID or filesystem
namespace. Off Linux the opt-out is refused before anything runs, as the default launch
is: only ``killpg`` would remain there, and a process that leaves the launcher's group
would outlive a session that reported success.
"""

from __future__ import annotations

import contextlib
import contextvars
import ctypes
import errno
import hashlib
import os
import re
import select
import shutil
import signal
import socket
import struct
import subprocess
import sys
import time
from collections.abc import Iterator
from pathlib import Path

from nexus_symbiote.core.hashing import open_regular_file

_ISOLATION: contextvars.ContextVar[bool] = contextvars.ContextVar(
    "nexus_symbiote_pinned_isolation", default=True
)
_LAUNCHER_BUDGET = 128 * 1024 * 1024
_NAMESPACE_OK: bool | None = None
_NAMESPACED: set[int] = set()
_INITS: dict[int, int] = {}
_RELEASE = b"\n"
_START_SECONDS = 5.0
# Opt-out launches only: session id, a private cgroup and, when the subreaper wrapper is
# the process, this process's end of the socket it writes its last byte to; recorded
# while the pid is live.
_OPT_OUT: dict[int, tuple[int | None, Path | None, int | None]] = {}
_CGROUP_SEQ = 0
_STOP_SECONDS = 1.0
_SWEEP_PASSES = 8
_TEARDOWN_SECONDS = 5.0
# Reads of the stopped wrapper's children that must find none running before the drain
# ends; a child that exits between two reads has its own children listed by the next.
_QUIET_READS = 50
# The credentials of a Unix-socket message, and how many messages cleanup reads looking
# for the wrapper's byte among any that a process holding a copy of its end wrote.
_UCRED = struct.Struct("3i")
_CHANNEL_MESSAGES = 64
# Runs in a fresh interpreter, so the caller executes no Python between fork and exec.
# The interpreter ignores SIGPIPE and SIGXFSZ at startup and adds LC_CTYPE under the C
# locale, so the wrapper restores both signals and passes the launch environment itself.
_SUBREAPER_EXEC = """\
import ctypes, os, select, signal, sys
# The wrapper writes one byte to this socket once no child of it is left; exec closes it.
done = int(sys.argv[2])
os.set_inheritable(done, False)
PR_SET_PDEATHSIG = 1
PR_SET_DUMPABLE = 4
PR_SET_CHILD_SUBREAPER = 36
prctl = ctypes.CDLL(None).prctl
prctl.argtypes = [ctypes.c_int] + [ctypes.c_ulong] * 4


def finish(status):
    # Reached only once every child has been reaped, so nothing the wrapper adopted
    # is still running; a wrapper that is killed never writes the byte.
    try:
        os.write(done, b"\\n")
    except OSError:
        pass
    code = os.waitstatus_to_exitcode(status)
    if code < 0:
        # Die of the launcher's signal; SIGKILL and SIGSTOP keep their only disposition.
        try:
            signal.signal(-code, signal.SIG_DFL)
        except (OSError, ValueError):
            pass
        os.kill(os.getpid(), -code)
    os._exit(code & 0xFF)


def children():
    me = os.getpid()
    try:
        with open(f"/proc/{me}/task/{me}/children", "rb") as listing:
            return [int(child) for child in listing.read().split()]
    except (OSError, ValueError):
        pass
    found = []
    for entry in os.listdir("/proc"):
        if entry.isdigit():
            try:
                with open(f"/proc/{entry}/stat", "rb") as stat:
                    if int(stat.read().rpartition(b")")[2].split()[1]) == me:
                        found.append(int(entry))
            except (OSError, ValueError, IndexError):
                pass
    return found


# A process that is not dumpable cannot be traced, or have its /proc descriptors
# opened, by another process of the same user, and it dumps no core of its own when it
# repeats the launcher's signal. Exec makes the launcher dumpable again.
parent = int(sys.argv[3])
if (
    prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0
    or prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) != 0
    # A stopped wrapper runs no check, so the caller's death resumes it; a running one
    # ignores this, and the fork clears it for the launcher.
    or prctl(PR_SET_PDEATHSIG, signal.SIGCONT, 0, 0, 0) != 0
    or os.getppid() != parent
):
    finish(127 << 8)
try:
    handle = open("cgroup", "rb")
except OSError:
    handle = None
if handle is not None:
    # Join before exec, so a clone(CLONE_PARENT) in the pinned bytes is born here.
    with handle:
        raw = handle.read(4096).split(b"\\n", 1)[0]
    if raw.startswith(b"/") and b".." not in raw.split(b"/"):
        try:
            with open(raw + b"/cgroup.procs", "w", encoding="ascii") as procs:
                procs.write(str(os.getpid()))
        except OSError:
            pass
signal.signal(signal.SIGPIPE, signal.SIG_DFL)
signal.signal(signal.SIGXFSZ, signal.SIG_DFL)
# The wrapper ignores every signal it can, from before the launcher exists, so the
# launcher cannot end it with a signal to its parent or to a group; SIGKILL remains.
# The launcher gets back the dispositions it would have had without the wrapper.
inherited = {}
for number in signal.valid_signals():
    if number != signal.SIGCHLD:
        try:
            inherited[number] = signal.signal(number, signal.SIG_IGN)
        except (OSError, ValueError):
            pass
# The wrapper stays alive as the launcher's parent and subreaper. A child the launcher
# starts with clone(CLONE_PARENT) is then the wrapper's, and so is every orphan below
# it, so cleanup finds them in the wrapper's tree on any host. The child execs below.
try:
    launcher = os.fork()
except OSError:
    finish(127 << 8)
if launcher:
    # Keep no copy of the launcher's streams, so their end of file is the launcher's.
    null = os.open(os.devnull, os.O_RDWR)
    os.dup2(null, 0)
    os.dup2(null, 1)
    os.close(null)
    # Blocked only here, after the fork, so SIGCHLD can be awaited with a timeout; a
    # child that exited before the block is reaped by the next pass all the same.
    signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGCHLD})
    # The caller's end of the socket closes when it gives up the launch, as an
    # interrupted spawn does, or when it dies.
    watch = select.poll()
    watch.register(done, getattr(select, "POLLRDHUP", 0))
    status = 0
    while True:
        try:
            while True:
                child, waited = os.waitpid(-1, os.WNOHANG)
                if child == 0:
                    break
                if child == launcher:
                    status = waited
        except ChildProcessError:
            break
        if os.getppid() != parent or watch.poll(0):
            # The process that started the session is gone or has given it up, a thread
            # exiting is not enough, and nothing else will end what the launcher started.
            for child in children():
                try:
                    os.kill(child, signal.SIGKILL)
                except OSError:
                    pass
        signal.sigtimedwait({signal.SIGCHLD}, 0.5)
    finish(status)
for number, previous in inherited.items():
    signal.signal(number, signal.SIG_IGN if previous == signal.SIG_IGN else signal.SIG_DFL)
# Its own process group, so a signal the launcher sends its group skips the wrapper.
os.setpgid(0, 0)
os.execve(sys.argv[1], [sys.argv[1]], {"PATH": os.defpath})
"""
# The namespace init runs this before the pinned bytes and waits for one byte on stdin.
# The caller writes it once it holds a pidfd for the init, so no launcher code can leave
# unshare's process group, kill unshare through it, or exit before cleanup can reach it.
_GATE_EXEC = """\
import os, signal, sys
if os.read(0, 1) != b"\\n":
    os._exit(127)
signal.signal(signal.SIGPIPE, signal.SIG_DFL)
signal.signal(signal.SIGXFSZ, signal.SIG_DFL)
os.execve(sys.argv[1], [sys.argv[1]], {"PATH": os.defpath})
"""


class PinnedProcessError(OSError):
    """The pinned launcher could not be staged or isolated."""

    def __init__(self, reason: str, message: str) -> None:
        super().__init__(message)
        self.reason = reason


def isolation_enabled() -> bool:
    return _ISOLATION.get()


def opt_out_supported() -> bool:
    """Whether this host may run an opted-out launch: only Linux has the subreaper
    wrapper and the /proc sweep that reach a process leaving the launcher's group."""
    return sys.platform.startswith("linux")


@contextlib.contextmanager
def isolation_off() -> Iterator[None]:
    """Explicitly accept a launch without kernel containment; descendants can escape.

    Only on Linux: elsewhere every launch in this context is refused with
    ``isolation-unavailable`` before anything is executed.
    """
    token = _ISOLATION.set(False)
    try:
        yield
    finally:
        _ISOLATION.reset(token)


def stage_pinned_executable(command: str, digest: str, work: Path) -> Path:
    """Copy the exact bytes of ``command`` to ``work/server`` and check ``digest``."""
    if (
        os.name != "posix"
        or not Path(command).is_absolute()
        or not re.fullmatch(r"sha256:[0-9a-f]{64}", digest)
    ):
        raise PinnedProcessError(
            "invalid-launch-policy", "expected an absolute POSIX executable and its SHA-256 pin"
        )
    staged = work / "server"
    hasher = hashlib.sha256()
    budget = _LAUNCHER_BUDGET
    try:
        with open_regular_file(Path(command)) as source, staged.open("xb") as out:
            if os.fstat(source.fileno()).st_size > budget:
                raise PinnedProcessError("launcher-unavailable", "launcher exceeds byte budget")
            while chunk := source.read(1024 * 1024):
                budget -= len(chunk)
                if budget < 0:
                    raise PinnedProcessError("launcher-unavailable", "launcher exceeds byte budget")
                hasher.update(chunk)
                out.write(chunk)
    except PinnedProcessError:
        raise
    except OSError as exc:
        raise PinnedProcessError("launcher-unavailable", "launcher cannot be read") from exc
    if digest != "sha256:" + hasher.hexdigest():
        raise PinnedProcessError(
            "launcher-digest-mismatch", "launcher differs from approved digest"
        )
    staged.chmod(0o500)
    return staged


def _unshare_path() -> str | None:
    found = shutil.which("unshare", path=os.defpath)
    if found is None or not Path(found).is_absolute():
        return None
    return found


def namespace_available() -> bool:
    """Whether this process can start a user and PID namespace.

    The result is cached. Ubuntu 24.04 with AppArmor's unprivileged-user-namespace
    restriction returns false; the probe is one short ``unshare`` of ``/bin/true``.
    Only Linux has these namespaces, so elsewhere it is false without a probe.
    """
    global _NAMESPACE_OK
    if not sys.platform.startswith("linux"):
        return False
    if _NAMESPACE_OK is None:
        _NAMESPACE_OK = _probe_namespace()
    return _NAMESPACE_OK


def _probe_namespace() -> bool:
    tool = _unshare_path()
    true_bin = shutil.which("true", path=os.defpath)
    if tool is None or true_bin is None or not Path(true_bin).is_absolute():
        return False
    try:
        result = subprocess.run(  # noqa: S603
            [
                tool,
                "--user",
                "--map-root-user",
                "--pid",
                "--fork",
                "--kill-child",
                "--",
                true_bin,
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=2,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return result.returncode == 0


def isolated_argv(staged: Path) -> list[str]:
    """The argv that runs ``staged``.

    A PID namespace is required unless the operator explicitly opted out. A PPid
    tree sweep cannot contain children that daemonize and are reparented, so an
    opted-out launch on Linux makes the launcher a child subreaper first.
    """
    return _launch_argv(staged)[0]


def _launch_argv(staged: Path) -> tuple[list[str], bool, bool]:
    """Return the launch argv, whether it uses the namespace gate, and whether it uses a subreaper."""
    if not isolation_enabled():
        if not opt_out_supported():
            raise PinnedProcessError(
                "isolation-unavailable",
                "the isolation opt-out is refused off Linux, where cleanup cannot reach a "
                "process that leaves the launcher's process group; no launcher was executed",
            )
        wrapper = _subreaper_argv(staged)
        return wrapper or [str(staged)], False, wrapper is not None
    # Off Linux an ``unshare`` on the default path is not util-linux's, and confirming
    # the teardown reads /proc, so no launch there may count as contained.
    if not sys.platform.startswith("linux") or not namespace_available():
        raise PinnedProcessError(
            "isolation-unavailable",
            "kernel PID containment is unavailable; no launcher was executed. "
            "Explicitly opt out only in an independently isolated worker",
        )
    tool = _unshare_path()
    if tool is None:
        raise PinnedProcessError("isolation-unavailable", "PID namespace launcher is unavailable")
    gate = _gate_argv(staged)
    # --kill-child is a parent-death signal, which the launcher can clear, so cleanup
    # kills the namespace init itself; the flag covers an unshare that dies first.
    argv = [tool, "--user", "--map-root-user", "--pid", "--fork", "--kill-child", "--"]
    return [*argv, *(gate or [str(staged)])], gate is not None, False


def _parent(pid: int) -> int | None:
    """The parent of ``pid`` from ``/proc/<pid>/stat``, or None if it cannot be read.

    The command name before the last ``)`` is raw bytes that any process can set, so
    only the fields after it are parsed.
    """
    try:
        with open(f"/proc/{pid}/stat", "rb") as stat:
            return int(stat.read().rpartition(b")")[2].split()[1])
    except (OSError, ValueError, IndexError):
        return None


def _children_by_parent() -> dict[int, list[int]]:
    """Each parent pid's children, from one scan of ``/proc``; OSError if it is unreadable."""
    children: dict[int, list[int]] = {}
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        parent = _parent(int(entry))
        if parent is not None:
            children.setdefault(parent, []).append(int(entry))
    return children


def _descendant_pids(root: int) -> set[int]:
    """Process-tree descendants of ``root``, including those that called ``setsid``."""
    try:
        children = _children_by_parent()
    except OSError:
        return set()
    found: set[int] = set()
    stack = [root]
    while stack:
        current = stack.pop()
        for child in children.get(current, ()):
            if child not in found:
                found.add(child)
                stack.append(child)
    return found


def _kill_descendants(root: int) -> None:
    """SIGKILL the descendant tree until a scan finds no descendant it has not signalled.

    A killed process cannot complete another fork, and a child it forked before the
    signal is found by the next scan, under ``root`` once its parent has died, because
    a living subreaper ``root`` adopts it. Zombies stay in the tree until reaped, so a
    scan counts only descendants not yet signalled. A process that keeps forking faster
    than the scans can outlast the bounded passes.
    """
    signalled: set[int] = set()
    for _ in range(_SWEEP_PASSES):
        victims = _descendant_pids(root) - signalled
        if not victims:
            return
        for victim in victims:
            try:
                os.kill(victim, signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                # It exited after the /proc scan, or it runs as another user and cannot be
                # signalled. Neither may stop cleanup before the launcher's group is killed.
                pass
        signalled |= victims


def _stop_tree(root: int) -> None:
    """SIGSTOP every descendant of the stopped ``root`` until a scan finds none running.

    A stopped process can neither fork nor reap, so a watchdog anywhere in the tree
    cannot restart a helper that the sweep kills, and no pid the sweep finds is freed
    for reuse before it is signalled. Bounded like the stop of ``root``: a process that
    is blocked in the kernel is swept while it may still run, and one this process may
    not signal is left to the sweep and the drain.
    """
    refused: set[int] = set()
    deadline = time.monotonic() + _STOP_SECONDS
    delay = 0.0005
    while True:
        running = [
            pid
            for pid in _descendant_pids(root) - refused
            if (fields := _proc_fields(pid)) is not None and fields[0] not in {"T", "t", "Z", "X"}
        ]
        if not running or time.monotonic() >= deadline:
            return
        for pid in running:
            try:
                # A pid that exited after the scan is no longer running, as wanted.
                with contextlib.suppress(ProcessLookupError):
                    os.kill(pid, signal.SIGSTOP)
            except PermissionError:
                refused.add(pid)
        time.sleep(delay)
        delay = min(delay * 2, 0.02)


def _stop_launcher(pid: int) -> int | None:
    """Stop the opted-out wrapper, or ``unshare``, so it cannot fork or reap during cleanup.

    A stopped wrapper is still alive, so on Linux it stays the subreaper that adopts the
    children of every descendant the sweep kills. The kernel reports the stop only once
    every thread has stopped, which a thread does on its way out of the kernel, so a fork
    in progress has attached its child by then. The wait is bounded: a launcher that is
    traced or blocked in the kernel is swept while it may still run. Returns the
    ``si_code`` of the stop or exit that was seen, or None if neither was.
    """
    try:
        os.kill(pid, signal.SIGSTOP)
    except (ProcessLookupError, PermissionError):
        # It is gone, or not ours to signal; the sweep and killpg still run.
        return None
    deadline = time.monotonic() + _STOP_SECONDS
    delay = 0.0005
    while True:
        try:
            # WNOWAIT leaves the exit status for the caller's wait().
            changed = os.waitid(os.P_PID, pid, os.WSTOPPED | os.WEXITED | os.WNOHANG | os.WNOWAIT)
        except OSError:
            # Not a child this process can wait for, or a system without these flags.
            return None
        if changed is not None:
            return changed.si_code
        if time.monotonic() >= deadline:
            return None
        time.sleep(delay)
        delay = min(delay * 2, 0.02)


def _children_of(pid: int) -> list[int]:
    """The children of ``pid``, from the kernel's list for its main thread where it exists.

    The wrapper runs one thread, so that list holds every child it has. Without
    ``CONFIG_PROC_CHILDREN`` the list is taken from one scan of ``/proc``. Raises
    OSError when neither can be read: no list is not the same as no child.
    """
    try:
        with open(f"/proc/{pid}/task/{pid}/children", "rb") as listing:
            return [int(child) for child in listing.read().split()]
    except (OSError, ValueError):
        pass
    return _children_by_parent().get(pid, [])


def _drain_children(pid: int) -> bool:
    """SIGKILL each running child of the stopped wrapper until none is left running.

    Every orphan below the wrapper is reparented to it, and a stopped wrapper reaps
    nothing, so a pid it lists stays that child's until the wrapper resumes: no signal
    sent here can reach a process that reused the pid, and a child seen to have ended
    stays so. A child whose main thread has exited reads as a zombie while its other
    threads run, so a child has ended only once its thread count has fallen to one.
    This catches a chain that forks and calls ``setsid`` faster than the tree sweep,
    one generation per read. Returns False when a child still runs at the deadline:
    one this process may not signal, or one that does not leave uninterruptible sleep,
    and when the wrapper's children cannot be listed at all.
    """
    deadline = time.monotonic() + _TEARDOWN_SECONDS
    signalled: set[int] = set()
    ended: set[int] = set()
    quiet = 0
    delay = 0.0005
    # Without the kernel's list each read scans all of /proc; two quiet reads in a row
    # still cover a child that exited between the listing and its state.
    needed = _QUIET_READS if os.path.exists(f"/proc/{pid}/task/{pid}/children") else 3
    while quiet < needed:
        running: set[int] = set()
        try:
            listed = _children_of(pid)
        except OSError:
            return False
        for child in listed:
            if child in ended:
                continue
            if _ended(child):
                ended.add(child)
            else:
                running.add(child)
        if not running:
            quiet += 1
            continue
        quiet = 0
        if time.monotonic() >= deadline:
            return False
        fresh = running - signalled
        for child in fresh:
            with contextlib.suppress(ProcessLookupError, PermissionError):
                os.kill(child, signal.SIGKILL)
        signalled |= fresh
        if fresh:
            delay = 0.0005
        else:
            time.sleep(delay)
            delay = min(delay * 2, 0.02)
    return True


def _let_the_wrapper_reap(pid: int) -> None:
    """Resume the stopped wrapper so it reaps the launcher's killed tree and exits.

    The wrapper is this module's own program, and the sweep and the drain have killed
    everything below it, so resuming it only lets it collect exit statuses: the launcher
    and its descendants are then reaped before the caller's ``wait()`` returns, rather
    than by pid 1 at some later time. Never used for a launcher run without the
    wrapper, which is untrusted. Bounded: a descendant that survived keeps the wrapper
    waiting, and its missing last byte then fails the cleanup.
    """
    with contextlib.suppress(ProcessLookupError, PermissionError):
        os.kill(pid, signal.SIGCONT)
    deadline = time.monotonic() + _STOP_SECONDS
    delay = 0.0005
    while time.monotonic() < deadline:
        try:
            # WNOWAIT leaves the exit status for the caller's wait().
            if os.waitid(os.P_PID, pid, os.WEXITED | os.WNOHANG | os.WNOWAIT) is not None:
                return
        except OSError:
            return
        time.sleep(delay)
        delay = min(delay * 2, 0.02)


def _alive(pid: int) -> bool:
    """Whether the child ``pid`` has not exited; False when that cannot be read."""
    try:
        return os.waitid(os.P_PID, pid, os.WEXITED | os.WNOHANG | os.WNOWAIT) is None
    except OSError:
        return False


def _wrapper_contained(pid: int, done: int, seen: int | None, stop: bool) -> bool:
    """Whether nothing the wrapper adopted can have outlived it; resumes it to reap.

    A wrapper that cleanup stopped holds every process the launcher started in its
    tree, so once none of its children runs while it is still alive, nothing can leave.
    A wrapper that had already exited shows that it reaped everything only by its last
    byte, which a wrapper the launcher killed never wrote. One killed during the drain
    had its children reparented past it before the drain could list them.
    """
    held = seen == os.CLD_STOPPED and _drain_children(pid) and _alive(pid)
    try:
        childless = held and not _children_of(pid)
    except OSError:
        # Unlisted, it may not have forked yet, so it dies stopped and nothing is confirmed.
        childless, held = True, False
    if childless:
        # Stopped before it forked, or once it had reaped everything. Resumed, the first
        # would start the launcher only now, after cleanup began, so it dies stopped.
        with contextlib.suppress(ProcessLookupError, PermissionError):
            os.kill(pid, signal.SIGKILL)
        return held
    if stop:
        _let_the_wrapper_reap(pid)
    return held or _wrapper_finished(done, pid)


def _wrapper_finished(done: int, wrapper: int) -> bool:
    """Whether the wrapper wrote its last byte, which it does only once it has no child.

    A wrapper that a launcher killed, or that cleanup had to kill, never writes it, and
    what it had adopted is then reparented past it, out of this cleanup's reach. The
    channel is a socket because a process of the same user can reopen this process's
    end of a pipe for writing through ``/proc/<pid>/fd`` and forge the byte, while
    opening a socket that way fails. A process that copied the wrapper's end, as one of
    the same user can with ``pidfd_getfd`` before the wrapper makes itself undumpable,
    could still write it, so only a byte the kernel credits to the wrapper's pid counts;
    claiming another pid needs ``CAP_SYS_ADMIN``. The wrapper is unreaped until the
    caller waits, so its pid names no other process.
    """
    channel = socket.socket(fileno=os.dup(done))
    try:
        poller = select.poll()
        poller.register(channel.fileno(), select.POLLIN)
        deadline = time.monotonic() + _STOP_SECONDS
        for _ in range(_CHANNEL_MESSAGES):
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not poller.poll(max(1, int(remaining * 1000))):
                return False
            try:
                data, ancillary, _, _ = channel.recvmsg(
                    16, socket.CMSG_SPACE(_UCRED.size), socket.MSG_DONTWAIT
                )
            except BlockingIOError:
                continue
            except OSError:
                return False
            if not data:
                # End of file: every writer has closed its end without the byte.
                return False
            senders = [
                _UCRED.unpack(payload[: _UCRED.size])[0]
                for level, kind, payload in ancillary
                if level == socket.SOL_SOCKET
                and kind == socket.SCM_CREDENTIALS
                and len(payload) >= _UCRED.size
            ]
            # The kernel never joins the bytes of two writers into one read.
            if data == b"\n" and senders == [wrapper]:
                return True
        return False
    finally:
        channel.close()


def _wrapper_channel() -> tuple[int, int]:
    """A connected socket pair for the wrapper's last byte; the wrapper's end is above 2.

    ``Popen`` places the launcher's streams on descriptors 0 to 2 after it keeps
    ``pass_fds``, so the wrapper's end there would be replaced.
    """
    left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    # Every write then carries its sender's credentials, stamped by the kernel.
    left.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
    done, finished = left.detach(), right.detach()
    low: list[int] = []
    while finished < 3:
        low.append(finished)
        finished = os.dup(finished)
    for descriptor in low:
        os.close(descriptor)
    return done, finished


def _status(pid: int) -> dict[str, str] | None:
    """The fields of ``/proc/<pid>/status``, or None once the pid no longer exists.

    The kernel escapes newlines, tabs and backslashes in the ``Name`` field but passes
    other bytes through, so a name that is not UTF-8 is decoded with escapes.
    """
    try:
        with open(f"/proc/{pid}/status", encoding="utf-8", errors="surrogateescape") as status:
            return dict(line.rstrip("\n").split(":\t", 1) for line in status if ":\t" in line)
    except (FileNotFoundError, ProcessLookupError):
        return None


def _ended(pid: int) -> bool:
    """Whether ``pid`` has finished exiting, or cannot be shown not to have.

    The init of a PID namespace becomes a zombie only after the kernel has killed every
    other process in the namespace and waited for them. A thread-group leader that exits
    while another thread runs is a zombie too, so the thread count must have fallen to
    the leader alone. A status that cannot be read is not taken as an exit.
    """
    try:
        status = _status(pid)
    except (OSError, ValueError):
        return False
    if status is None:
        return True
    return status.get("State", "")[:1] in {"Z", "X"} and status.get("Threads") == "1"


def _end_namespace(supervisor: int) -> bool:
    """SIGKILL each child of the stopped ``unshare`` and wait until the kernel ends it.

    A launcher can clear the parent-death signal that ``--kill-child`` sets and leave
    the process group that killpg reaches. A SIGKILL from the parent namespace always
    reaches the namespace init, and the kernel then kills every process in the
    namespace, nested namespaces included. While ``unshare`` is stopped it cannot reap
    its child, so the child's pid cannot be reused before it is signalled and seen to
    exit. Returns False when the scan fails or the deadline passes first.
    """
    try:
        inits = _children_by_parent().get(supervisor, [])
    except OSError:
        return False
    for pid in inits:
        with contextlib.suppress(ProcessLookupError, PermissionError):
            os.kill(pid, signal.SIGKILL)
    deadline = time.monotonic() + _TEARDOWN_SECONDS
    delay = 0.0005
    while inits := [pid for pid in inits if not _ended(pid)]:
        if time.monotonic() >= deadline:
            return False
        time.sleep(delay)
        delay = min(delay * 2, 0.02)
    return True


def _end_init(init: int) -> bool:
    """SIGKILL the namespace init through its pidfd and wait until the namespace has ended.

    The pidfd becomes readable once the init has exited and every thread of it is gone,
    which the kernel allows only after it has killed and reaped every other process in
    the namespace. A pidfd keeps naming the init after ``unshare`` has died, even once
    its pid has been reaped and reused. Returns False when the deadline passes first.
    """
    with contextlib.suppress(ProcessLookupError):
        signal.pidfd_send_signal(init, signal.SIGKILL)
    poller = select.poll()
    poller.register(init, select.POLLIN)
    events = poller.poll(int(_TEARDOWN_SECONDS * 1000))
    return any(revents & select.POLLIN for _, revents in events)


def _end_unheld_namespace(proc: subprocess.Popen[bytes], stop: bool) -> bool:
    """End a namespace whose init the caller holds no pidfd for, or report that it cannot.

    A stopped ``unshare`` keeps its child's pid from being reaped and reused. If it has
    already exited, it reaped the init first, so the namespace has ended; if a signal
    killed it, the init may have cleared its parent-death signal and outlived it.
    """
    if not stop:
        return proc.returncode is not None and proc.returncode >= 0
    seen = _stop_launcher(proc.pid)
    if seen == os.CLD_STOPPED:
        return _end_namespace(proc.pid)
    return seen == os.CLD_EXITED


def _interpreter() -> str | None:
    """This interpreter, when a fixed exec wrapper can run it, or None."""
    interpreter = sys.executable
    if (
        not sys.platform.startswith("linux")
        or getattr(sys, "frozen", False)
        or not interpreter
        or not Path(interpreter).is_absolute()
    ):
        return None
    return interpreter


def _pidfd_supported() -> bool:
    return hasattr(os, "pidfd_open") and hasattr(signal, "pidfd_send_signal")


def _gate_argv(staged: Path) -> list[str] | None:
    """Run ``staged`` as the namespace init only once it is released, or None.

    The wrapper has the same constraints as the subreaper wrapper. Without a separately
    runnable interpreter, ``os.pidfd_open`` or ``signal.pidfd_send_signal``, the init
    starts at once, and cleanup finds it as the child of a stopped ``unshare`` instead.
    """
    interpreter = _interpreter()
    if interpreter is None or not _pidfd_supported():
        return None
    return [interpreter, "-I", "-S", "-B", "-c", _GATE_EXEC, str(staged)]


def _exited(pid: int) -> bool:
    try:
        return os.waitid(os.P_PID, pid, os.WEXITED | os.WNOHANG | os.WNOWAIT) is not None
    except OSError:
        return False


def _namespace_init(supervisor: int, depth: int) -> int | None:
    """The child of ``supervisor`` that is pid 1 of a PID namespace one level deeper."""
    for child in _children_by_parent().get(supervisor, []):
        status = _status(child)
        nspid = status.get("NSpid", "").split() if status is not None else []
        if len(nspid) == depth + 1 and nspid[-1] == "1":
            return child
    return None


def _hold_init(supervisor: int) -> int | None:
    """A pidfd for the namespace init of ``supervisor``, which waits in the gate.

    The pid is read again after the pidfd is opened: it is still the child of
    ``unshare``, which forks once, so the pidfd names the init and not a process that
    reused its pid. Returns None when ``/proc`` or the kernel cannot provide a verified
    pidfd; cleanup then falls back to stopping ``unshare``. Raises
    ``PinnedProcessError`` when no init starts, before any launcher code has run.
    """
    if not _pidfd_supported():
        return None
    try:
        status = _status(supervisor)
    except OSError:
        return None
    depth = len(status.get("NSpid", "").split()) if status is not None else 0
    if depth == 0:
        return None
    deadline = time.monotonic() + _START_SECONDS
    delay = 0.0005
    while True:
        try:
            init = _namespace_init(supervisor, depth)
        except OSError:
            return None
        if init is not None:
            break
        if _exited(supervisor) or time.monotonic() >= deadline:
            raise PinnedProcessError(
                "isolation-unavailable",
                "the PID namespace init did not start; no launcher was executed",
            )
        time.sleep(delay)
        delay = min(delay * 2, 0.02)
    try:
        pidfd = os.pidfd_open(init)
    except OSError:
        return None
    if _parent(init) == supervisor:
        return pidfd
    os.close(pidfd)
    raise PinnedProcessError(
        "isolation-unavailable", "the PID namespace init exited before the launcher was executed"
    )


def _current_cgroup() -> Path | None:
    """This process's cgroup v2 directory, or None when that hierarchy is absent."""
    try:
        text = Path("/proc/self/cgroup").read_text(encoding="ascii")
    except (OSError, ValueError):
        return None
    for line in text.splitlines():
        identity, controllers, path = (line.split(":", 2) + ["", ""])[:3]
        if identity == "0" and controllers == "" and path.startswith("/"):
            root = Path("/sys/fs/cgroup" + path)
            if (root / "cgroup.controllers").is_file() and (root / "cgroup.kill").is_file():
                return root
    return None


def _prepare_cgroup(work: Path) -> Path | None:
    """A private child cgroup for one opt-out launch, or None when it cannot be made.

    The path is written to ``work/cgroup`` for the exec wrapper, which joins before it
    runs the pinned bytes. ``cgroup.kill`` then reaches a ``clone(CLONE_PARENT)`` child
    that has left the process session: its parent is this process, so the descendant
    walk does not see it, and ``setsid`` takes it out of ``killpg``.
    """
    global _CGROUP_SEQ
    root = _current_cgroup()
    if root is None:
        return None
    _CGROUP_SEQ += 1
    path = root / f"nexus-symbiote-{os.getpid()}-{_CGROUP_SEQ}"
    try:
        path.mkdir()
    except OSError:
        return None
    if not (path / "cgroup.kill").is_file():
        path.rmdir()
        return None
    try:
        (work / "cgroup").write_text(str(path), encoding="ascii")
    except OSError:
        path.rmdir()
        return None
    return path


def _move_into_cgroup(path: Path, pid: int) -> None:
    with contextlib.suppress(OSError):
        (path / "cgroup.procs").write_text(str(pid), encoding="ascii")


def _cgroup_kill(path: Path) -> None:
    with contextlib.suppress(OSError):
        (path / "cgroup.kill").write_text("1", encoding="ascii")


def _remove_cgroup(path: Path) -> None:
    for attempt in range(5):
        try:
            path.rmdir()
            return
        except OSError as exc:
            if exc.errno != errno.EBUSY or attempt == 4:
                return
            time.sleep(0.02)


def _proc_fields(pid: int) -> list[str] | None:
    """``state``, ``ppid``, ``pgrp`` and ``session`` from ``/proc/<pid>/stat``.

    The launcher chooses the process name inside the parentheses, which may be any
    bytes, so it is decoded with escapes: a name must not stop the cleanup sweep.
    """
    try:
        with open(f"/proc/{pid}/stat", encoding="utf-8", errors="surrogateescape") as stat:
            text = stat.read()
    except OSError:
        return None
    fields = text.rpartition(")")[2].split()
    return fields if len(fields) >= 4 else None


def _kill_session(sid: int) -> None:
    """SIGKILL every process that still shares ``sid``, for a few bounded passes.

    ``killpg`` misses a member that called ``setpgid``. A ``setsid`` child has a new
    session and is not found here; the cgroup covers that case.
    """
    # Only a session that start_new_session made for the launch; never the caller's own.
    if sid <= 1 or sid == os.getsid(0):
        return
    own = os.getpid()
    for _ in range(_SWEEP_PASSES):
        try:
            entries = os.listdir("/proc")
        except OSError:
            return
        victims: list[int] = []
        for entry in entries:
            if not entry.isdigit():
                continue
            pid = int(entry)
            if pid in {own, 1}:
                continue
            fields = _proc_fields(pid)
            # An ended process, such as the unreaped wrapper that leads the session, would
            # otherwise keep every pass from finding the session empty.
            if fields is not None and fields[3] == str(sid) and not _ended(pid):
                victims.append(pid)
        if not victims:
            return
        for pid in victims:
            with contextlib.suppress(ProcessLookupError, PermissionError):
                os.kill(pid, signal.SIGKILL)


def _subreaper_argv(staged: Path) -> list[str] | None:
    """Run ``staged`` as the child of a wrapper that stays a child subreaper, or None.

    A double-fork calls ``setsid`` and then exits the intermediate process, so the
    grandchild's parent would otherwise become pid 1 and leave the descendant tree. The
    wrapper forks, the child execs the pinned bytes, and the wrapper stays alive,
    reaping and keeping no copy of the launcher's streams, until no child is left; then
    it writes one byte to the socket ``spawn_pinned`` appends to this argv, with the pid
    it must have as its parent, and exits with the launcher's status. Every orphan below it, a ``clone(CLONE_PARENT)`` child of
    the launcher (whose parent is the wrapper) and the descendants of a launcher that
    already exited are therefore in the wrapper's tree for the sweep. The launcher leads
    its own process group in the session its wrapper leads, with the signal dispositions
    it would have had without the wrapper, while the wrapper ignores every signal it can.
    The wrapper runs before the pinned bytes, with this interpreter, a fixed program,
    the fixed launch environment and ``-I -S``, so environment variables, the working
    directory and site-packages do not reach it. Only Linux has
    ``PR_SET_CHILD_SUBREAPER``, and elsewhere the opt-out is refused; without prctl or a
    separately runnable interpreter, an opted-out launch keeps best-effort cleanup. The calling process
    is never marked.
    """
    interpreter = _interpreter()
    if interpreter is None:
        return None
    try:
        if not hasattr(ctypes.CDLL(None), "prctl"):
            return None
    except OSError:
        return None
    return [interpreter, "-I", "-S", "-B", "-c", _SUBREAPER_EXEC, str(staged)]


def _executable_image(staged: Path) -> bool:
    """True when the kernel can exec the file directly: ELF or a shebang script.

    ``unshare`` and the subreaper wrapper execute the launcher themselves, so an exec
    failure there looks like an empty MCP session. Checking the image first keeps a
    file that is neither an ELF image nor a script ``launcher-start-failed`` on every
    launch path.
    """
    try:
        with staged.open("rb") as handle:
            prefix = handle.read(4)
    except OSError:
        return False
    return prefix.startswith(b"\x7fELF") or prefix.startswith(b"#!")


def spawn_pinned(staged: Path, work: Path) -> subprocess.Popen[bytes]:
    """Start the staged launcher with a private cwd, a default PATH and a new session.

    No Python runs in the child between fork and exec: that is unsafe in a threaded
    caller, and ``Popen`` would wait for it before any protocol deadline exists. The
    subreaper wrapper does its work after exec, within the caller's deadline. When this
    process dies without cleaning up, the wrapper notices within half a second and
    kills the launcher's tree. A namespace init waits in the gate until this process
    holds a pidfd for it, at most ``_START_SECONDS``.
    """
    if not _executable_image(staged):
        raise PinnedProcessError("launcher-start-failed", "launcher could not be run")
    namespaced = isolation_enabled()
    cgroup: Path | None = None
    done: int | None = None
    finished: int | None = None
    try:
        argv, gated, wrapped = _launch_argv(staged)
        if wrapped:
            # Only the wrapper can join the cgroup before the pinned bytes run.
            cgroup = _prepare_cgroup(work)
            done, finished = _wrapper_channel()
            argv = [*argv, str(finished), str(os.getpid())]
        proc = subprocess.Popen(  # noqa: S603
            argv,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            cwd=work,
            env={"PATH": os.defpath},
            start_new_session=True,
            bufsize=0,
            pass_fds=() if finished is None else (finished,),
        )
    except BaseException as exc:
        if done is not None:
            os.close(done)
        if cgroup is not None:
            _remove_cgroup(cgroup)
        if isinstance(exc, PinnedProcessError) or not isinstance(exc, OSError):
            raise
        raise PinnedProcessError("launcher-start-failed", "launcher could not be run") from exc
    finally:
        # Only the wrapper may hold its end, so its exit is the channel's end of file.
        if finished is not None:
            os.close(finished)
    if namespaced:
        _NAMESPACED.add(proc.pid)
    else:
        if cgroup is not None:
            _move_into_cgroup(cgroup, proc.pid)
        try:
            sid: int | None = os.getsid(proc.pid)
        except OSError:
            sid = None
        _OPT_OUT[proc.pid] = (sid, cgroup, done)
    if gated:
        _release(proc)
    return proc


def _release(proc: subprocess.Popen[bytes]) -> None:
    """Hold the namespace init, then let it execute the launcher; on failure, end it."""
    assert proc.stdin is not None and proc.stdout is not None
    init: int | None = None
    try:
        init = _hold_init(proc.pid)
        os.write(proc.stdin.fileno(), _RELEASE)
    except BaseException as exc:
        # The init still waits in the gate, with the parent-death signal set, so killing
        # unshare ends it before any launcher code runs.
        with contextlib.suppress(ProcessLookupError, PermissionError):
            os.killpg(proc.pid, signal.SIGKILL)
        if init is not None:
            with contextlib.suppress(OSError):
                os.close(init)
        _NAMESPACED.discard(proc.pid)
        proc.stdin.close()
        proc.stdout.close()
        proc.wait()
        if isinstance(exc, PinnedProcessError) or not isinstance(exc, OSError):
            raise
        raise PinnedProcessError("launcher-start-failed", "launcher could not be run") from exc
    if init is not None:
        _INITS[proc.pid] = init


def terminate_process_group(proc: subprocess.Popen[bytes]) -> bool:
    """Clean up the launch and return whether its containment was verified.

    In a PID namespace, the init is killed through the pidfd taken at launch, and
    cleanup waits until the kernel has ended the namespace. Without that pidfd,
    ``unshare`` is stopped so that it cannot reap the init, and the init is found as its
    child. If the namespace cannot be confirmed ended by the deadline, or ``unshare``
    was killed before cleanup with no pidfd held, ``unshare`` is still killed and
    ``PinnedProcessError`` reports ``isolation-teardown-failed``.

    Outside a namespace, on Linux, the launcher runs as the child of a wrapper that
    stays alive as a child subreaper. A double-fork, a ``clone(CLONE_PARENT)`` child and
    a descendant of a launcher that already exited are all reparented to the wrapper
    instead of pid 1 or this process, so the tree sweep from the wrapper finds them,
    whatever session or group they moved to. The wrapper is stopped first, so it stays
    alive to adopt the children of each process the sweep kills; a helper the launcher
    restarts during the sweep is its child and is found by the next pass, and what still
    runs after the passes is killed as it is reparented to the stopped wrapper. Resumed,
    the wrapper reaps everything and exits, writing one last byte once it has no child.
    When something below the stopped wrapper could not be killed or listed, or the
    wrapper was already dead without having written that byte because the launcher killed it,
    ``PinnedProcessError`` reports ``isolation-teardown-failed``: what the wrapper had
    adopted may have outlived it.
    """
    namespaced = proc.pid in _NAMESPACED
    init = _INITS.pop(proc.pid, None)
    sid, cgroup, done = _OPT_OUT.pop(proc.pid, (None, None, None))
    # The sweep reads Linux's /proc, and macOS has no os.waitid before Python 3.13. Until
    # it is reaped, the pid is still this launcher's.
    stop = sys.platform.startswith("linux") and proc.returncode is None
    ended = True
    contained = True
    swept = False
    seen: int | None = None
    try:
        try:
            if namespaced:
                try:
                    ended = (
                        _end_init(init) if init is not None else _end_unheld_namespace(proc, stop)
                    )
                except Exception:
                    # Whatever failed, the namespace was not shown to have ended.
                    ended = False
            else:
                if stop:
                    seen = _stop_launcher(proc.pid)
                if seen == os.CLD_STOPPED:
                    _stop_tree(proc.pid)
                _kill_descendants(proc.pid)
            if done is not None:
                contained = _wrapper_contained(proc.pid, done, seen, stop)
            # Defense in depth after the wrapper check: the cgroup also holds any
            # process that left the wrapper's tree (or survived if the wrapper died).
            # Killing the cgroup before _wrapper_contained would kill the wrapper
            # before it can reap and confirm containment.
            if cgroup is not None:
                _cgroup_kill(cgroup)
            swept = True
        finally:
            if not swept and not namespaced:
                # Interrupted, by KeyboardInterrupt or an error: the launcher leads its own
                # group, which killpg does not reach, so its tree is swept while the
                # wrapper still adopts its orphans.
                with contextlib.suppress(Exception):
                    _kill_descendants(proc.pid)
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                # The group already exited; the caller's wait() still reaps the launcher.
                pass
            except PermissionError:
                # macOS refuses killpg with EPERM when the group holds only the exited
                # zombie OR briefly while the leader is mid-exit (XNU P_WEXIT) before
                # waitpid sees it. Wait briefly before concluding it is alive and unsignallable.
                if sys.platform.startswith("linux"):
                    raise
                if proc.poll() is None:
                    with contextlib.suppress(subprocess.TimeoutExpired):
                        proc.wait(timeout=0.1)
                    if proc.poll() is None:
                        raise
        if not namespaced:
            _kill_descendants(proc.pid)
    finally:
        # Only while the launch is unreaped: its pid, which is the session id, cannot
        # then name a session that a later, unrelated process started. Here so that an
        # interrupted cleanup still ends what is left in the session.
        if sid is not None and stop:
            with contextlib.suppress(Exception):
                _kill_session(sid)
        # A finished pid must not stay marked. The kernel can reuse it for a later
        # launcher that is not in a PID namespace, and that launcher would then skip
        # the descendant-tree kill.
        _NAMESPACED.discard(proc.pid)
        if done is not None:
            with contextlib.suppress(OSError):
                os.close(done)
        if init is not None:
            try:
                if hasattr(signal, "pidfd_send_signal"):
                    with contextlib.suppress(OSError):
                        signal.pidfd_send_signal(init, signal.SIGKILL)
            finally:
                with contextlib.suppress(OSError):
                    os.close(init)
        if cgroup is not None:
            if not swept:
                with contextlib.suppress(Exception):
                    _cgroup_kill(cgroup)
            _remove_cgroup(cgroup)
        if stop:
            # killpg has normally killed it already. If cleanup failed before that, a
            # stopped launcher would never read EOF and the caller's wait() would hang.
            with contextlib.suppress(ProcessLookupError, PermissionError):
                os.kill(proc.pid, signal.SIGKILL)
    if not ended:
        raise PinnedProcessError(
            "isolation-teardown-failed",
            "the launcher's PID namespace could not be confirmed ended; "
            "a process from it may still be running",
        )
    if not contained:
        raise PinnedProcessError(
            "isolation-teardown-failed",
            "the launcher's wrapper did not outlive everything it started; "
            "a process the launcher started may still be running",
        )
    return namespaced or done is not None
