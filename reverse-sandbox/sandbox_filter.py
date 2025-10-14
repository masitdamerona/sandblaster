#!/usr/bin/env python3

import struct
import re
import logging
import logging.config
import reverse_string

from filters import Filters
from modifiers import Modifiers


logging.config.fileConfig("logger.config")
logger = logging.getLogger(__name__)

keep_builtin_filters = False
global_vars = []


def get_filter_arg_string_by_offset(f, offset):
    """Extract string (literal) from given offset."""
    global base_addr
    f.seek(offset * 8 + base_addr)
    len = struct.unpack("<H", f.read(2))[0]
    f.seek(offset * 8 + base_addr)
    s = f.read(2+len)
    
    ss = reverse_string.SandboxString()
    myss = ss.parse_byte_string(s[2:], global_vars)
    actual_string = ""
    for sss in myss:
        actual_string = actual_string + sss + " "
    actual_string = actual_string[:-1]
    logger.info("actual string is " + actual_string)
    return myss


def get_filter_arg_string_by_offset_with_type(f, offset):
    """Extract string from given offset and consider type byte."""
    global keep_builtin_filters
    global base_addr

    f.seek(offset * 8 + base_addr)

    len = struct.unpack("<H", f.read(2))[0]
    f.seek(offset * 8 + base_addr)
    s = f.read(2 + len)
    logger.info("binary string is " + s.hex())
    ss = reverse_string.SandboxString()
    myss = ss.parse_byte_string(s[2:], global_vars)
    append = "literal"
    actual_string = ""

    for sss in myss:
        actual_string = actual_string + sss + " "
    actual_string = actual_string[:-1]
    logger.info("actual string is " + actual_string)

    return (append, myss)

def get_filter_arg_string_by_offset_no_skip(f, offset):
    """Extract string from given offset and ignore type byte."""
    global base_addr
    f.seek(offset * 8 + base_addr)
    string_len = struct.unpack("<H", f.read(2))[0]-1
    res = ""
    try:
        res = f.read(string_len).decode()
    except UnicodeDecodeError:
        res = "UNSUPPORTED"
    return res


def get_filter_arg_network_address(f, offset):
    """Convert 4 bytes value to network address (host and port)."""
    global base_addr
    f.seek(offset * 8 + base_addr)

    host, port = struct.unpack("<HH", f.read(4))
    host_port_string = ""
    if host == 0x1:
        proto = "ip4"
        host_port_string += "*"
    elif host == 0x2:
        proto = "ip6"
        host_port_string += "*"
    elif host == 0x3:
        proto = "ip"
        host_port_string += "*"
    elif host == 0x5:
        proto = "tcp4"
        host_port_string += "*"
    elif host == 0x6:
        proto = "tcp6"
        host_port_string += "*"
    elif host == 0x7:
        proto = "tcp"
        host_port_string += "*"
    elif host == 0x9:
        proto = "udp4"
        host_port_string += "*"
    elif host == 0xa:
        proto = "udp6"
        host_port_string += "*"
    elif host == 0xb:
        proto = "udp"
        host_port_string += "*"
    elif host == 0x101:
        proto = "ip4"
        host_port_string += "localhost"
    elif host == 0x102:
        proto = "ip6"
        host_port_string += "localhost"
    elif host == 0x103:
        proto = "ip"
        host_port_string += "localhost"
    elif host == 0x105:
        proto = "tcp4"
        host_port_string += "localhost"
    elif host == 0x106:
        proto = "tcp6"
        host_port_string += "localhost"
    elif host == 0x107:
        proto = "tcp"
        host_port_string += "localhost"
    elif host == 0x109:
        proto = "udp4"
        host_port_string += "localhost"
    elif host == 0x10a:
        proto = "udp6"
        host_port_string += "localhost"
    elif host == 0x10b:
        proto = "udp"
        host_port_string += "localhost"
    else:
        proto = "unknown"
        host_port_string += "0x%x" % host

    if port == 0:
        host_port_string += ":*"
    else:
        host_port_string += ":%d" % (port)
    return '%s "%s"' % (proto, host_port_string)


def get_filter_arg_integer(f, arg):
    """Convert integer value to decimal string representation."""
    return '%d' % arg


def get_filter_arg_octal_integer(f, arg):
    """Convert integer value to octal string representation."""
    return '#o%04o' % arg


def get_filter_arg_boolean(f, arg):
    """Convert boolean value to scheme boolean string representation."""
    if arg == 1:
        return '#t'
    else:
        return '#f'


regex_list = []
def get_filter_arg_regex_by_id(f, regex_id):
    """Get regular expression by index."""
    global keep_builtin_filters
    return_string = ""
    global regex_list
    # regex_list = list("regex_list")
    for regex in regex_list[regex_id]:
        if re.match("^/com\\\.apple\\\.sandbox\$", regex) and keep_builtin_filters == False:
            return "###$$$***"
        return_string += ' #"%s"' % (regex)
    return return_string[1:]


def get_filter_arg_ctl(f, arg):
    """Convert integer value to IO control string."""
    letter = chr(arg >> 8)
    number = arg & 0xff
    return '[UNSUPPORTED](_IO "%s" %d)' % (letter, number)


def get_filter_arg_vnode_type(f, arg):
    """Convert integer to file (vnode) type string."""
    arg_types = {
            0x01: "REGULAR-FILE",
            0x02: "DIRECTORY",
            0x03: "BLOCK-DEVICE",
            0x04: "CHARACTER-DEVICE",
            0x05: "SYMLINK",
            0x06: "SOCKET",
            0x07: "FIFO",
            0xffff: "TTY"
            }
    if arg in arg_types.keys():
        return '%s' % (arg_types[arg])
    else:
        return '%d' % arg

def get_filter_arg_signal_number(f, arg):
    """Convert integer to file (vnode) type string."""
    arg_types = {
            0x01: "SIGHUP",
            0x02: "SIGINT",
            0x03: "SIGQUIT",
            0x04: "SIGILL",
            0x05: "SIGTRAP",
            0x06: "SIGABRT",
            0x07: "SIGEMT",
            0x08: "SIGFPE",
            0x09: "SIGKILL",
            0x0a: "SIGBUS",
            0x0b: "SIGSEGV",
            0x0c: "SIGSYS",
            0x0d: "SIGPIPE",
            0x0e: "SIGALRM",
            0x0f: "SIGTERM",
            0x10: "SIGURG",
            0x11: "SIGSTOP",
            0x12: "SIGTSTP",
            0x13: "SIGCONT",
            0x14: "SIGCHLD",
            0x15: "SIGTTIN",
            0x16: "SIGTTOU",
            0x17: "SIGIO",
            0x18: "SIGXCPU",
            0x19: "SIGXFSZ",
            0x1a: "SIGVTALRM",
            0x1b: "SIGPROF",
            0x1c: "SIGWINCH",
            0x1d: "SIGINFO",
            0x1e: "SIGUSR1",
            0x1f: "SIGUSR2"
            }
    if arg in arg_types.keys():
        return '%s' % (arg_types[arg])
    else:
        return '%d' % arg

def get_filter_arg_file_attribute(f, arg):
    """Convert integer to file_attribute type string."""
    arg_types = {
            0: "sip-protected",
            1: "datavault",
            2: "time-machine-backup",
            3: "time-machine-device",
            4: "local-filesystem",
            5: "root-filesystem",
            6: "snapshot",
            7: "removable-media",
            8: "disk-image",
            9: "sip-protected-filesystem",
            10: "removable-device",
            11: "disk-image-device",
            12: "sip-protected-device",
            13: "apfs-synthetic",
            14: "apfs-preboot-volume",
            15: "apfs-recovery-volume",
            16: "union-mounted-filesystem",
            17: "rsr-cryptex",
            18: "protected-ancestor",
            19: "network-approval-exempt",
            20: "smb-home-mount-dir",
            21: "fileprovider-owned",
            22: "app-bundle",
            23: "app-bundle-containing-responsible-binary",
            }
    if arg in arg_types.keys():
        return '%s' % (arg_types[arg])
    else:
        return '%d' % arg

def get_filter_arg_iokit_usb(f, arg):
    """Convert integer to iokit_usb type string."""
    arg_types = {
            1: "kUSBAudioInterfaceClass",
            2: "kUSBCommunicationControlInterfaceClass",
            3: "kUSBHIDInterfaceClass",
            5: "kUSBPhysicalInterfaceClass",
            6: "kUSBImageInterfaceClass",
            7: "kUSBPrintingInterfaceClass",
            8: "kUSBMassStorageInterfaceClass",
            10: "kUSBCommunicationDataInterfaceClass",
            11: "kUSBChipSmartCardInterfaceClass",
            13: "kUSBContentSecurityInterfaceClass",
            14: "kUSBVideoInterfaceClass",
            15: "kUSBPersonalHealthcareInterfaceClass",
            220: "kUSBDiagnosticDeviceInterfaceClass",
            224: "kUSBWirelessControllerInterfaceClass",
            254: "kUSBApplicationSpecificInterfaceClass",
            255: "kUSBVendorSpecificInterfaceClass",
            }
    if arg in arg_types.keys():
        return '%s' % (arg_types[arg])
    else:
        return '%d' % arg

def get_filter_arg_storage_class_extension(f, arg):
    """Convert integer to storage_class_extention type string."""
    arg_types = {
            1: 'kUSBAudioInterfaceClass',
            2: 'kUSBCommunicationControlInterfaceClass',
            3: 'kUSBHIDInterfaceClass',
            5: 'kUSBPhysicalInterfaceClass',
            6: 'kUSBImageInterfaceClass',
            7: 'kUSBPrintingInterfaceClass',
            8: 'kUSBMassStorageInterfaceClass',
            10: 'kUSBCommunicationDataInterfaceClass',
            11: 'kUSBChipSmartCardInterfaceClass',
            13: 'kUSBContentSecurityInterfaceClass',
            14: 'kUSBVideoInterfaceClass',
            15: 'kUSBPersonalHealthcareInterfaceClass',
            220: 'kUSBDiagnosticDeviceInterfaceClass',
            224: 'kUSBWirelessControllerInterfaceClass',
            254: 'kUSBApplicationSpecificInterfaceClass',
            255: 'kUSBVendorSpecificInterfaceClass'
            }
    if arg in arg_types.keys():
        return '%s' % (arg_types[arg])
    else:
        return '%d' % arg

def get_filter_arg_iokit_usb_subclass(f, arg):
    """Convert integer to iokit_usb subclass type string."""
    arg_types = {
            0: "kUSBCompositeSubClass",
            # 0: "kUSBHubSubClass",
            1: "kUSBRFControllerSubClass",
            # 1: "kUSBVideoControlSubClass",
            # 1: "kUSBCommDirectLineSubClass",
            # 1: "kUSBDFUSubClass",
            # 1: "kUSBHIDBootInterfaceSubClass",
            # 1: "kUSBAudioControlSubClass",
            # 1: "kUSBMassStorageRBCSubClass",
            # 1: "kUSBReprogrammableDiagnosticSubClass",
            2: "kUSBMassStorageATAPISubClass",
            # 2: "kUSBCommonClassSubClass",
            # 2: "kUSBCommAbstractSubClass",
            # 2: "kUSBAudioStreamingSubClass",
            # 2: "kUSBIrDABridgeSubClass",
            # 2: "kUSBVideoStreamingSubClass",
            3: "kUSBTestMeasurementSubClass",
            # 3: "kUSBCommTelephoneSubClass",
            # 3: "kUSBMassStorageQIC157SubClass",
            # 3: "kUSBMIDIStreamingSubClass",
            # 3: "kUSBVideoInterfaceCollectionSubClass",
            4: "kUSBCommMultiChannelSubClass",
            # 4: "kUSBMassStorageUFISubClass",
            5: "kUSBCommCAPISubClass",
            # 5: "kUSBMassStorageSFF8070iSubClass",
            6: "kUSBCommEthernetNetworkingSubClass",
            # 6: "kUSBMassStorageSCSISubClass",
            7: "kUSBATMNetworkingSubClass",
            }
    if arg in arg_types.keys():
        return '%s' % (arg_types[arg])
    else:
        return '%d' % arg

def get_filter_arg_persona_type(f, arg):
    """Convert integer to persona_type type string."""
    arg_types = {
            0: 'PERSONA_INVALID',
            1: 'PERSONA_GUEST',
            2: 'PERSONA_MANAGED',
            3: 'PERSONA_PRIV',
            4: 'PERSONA_SYSTEM',
            5: 'PERSONA_DEFAULT',
            8: 'PERSONA_ENTERPRISE'}
    if arg in arg_types.keys():
        return '%s' % (arg_types[arg])
    else:
        return '%d' % arg

def get_filter_arg_syscall_number(f, arg):
    """Convert integer to syscall number type string."""
    arg_types = {
            0: 'SYS_syscall',
            1: 'SYS_exit',
            2: 'SYS_fork',
            3: 'SYS_read',
            4: 'SYS_write',
            5: 'SYS_open',
            8: 'PERSONA_ENTERPRISE',
            6: 'SYS_close',
            7: 'SYS_wait4',
            9: 'SYS_link',
            10: 'SYS_unlink',
            12: 'SYS_chdir',
            13: 'SYS_fchdir',
            14: 'SYS_mknod',
            15: 'SYS_chmod',
            16: 'SYS_chown',
            18: 'SYS_getfsstat',
            20: 'SYS_getpid',
            23: 'SYS_setuid',
            24: 'SYS_getuid',
            25: 'SYS_geteuid',
            26: 'SYS_ptrace',
            27: 'SYS_recvmsg',
            28: 'SYS_sendmsg',
            29: 'SYS_recvfrom',
            30: 'SYS_accept',
            31: 'SYS_getpeername',
            32: 'SYS_getsockname',
            33: 'SYS_access',
            34: 'SYS_chflags',
            35: 'SYS_fchflags',
            36: 'SYS_sync',
            37: 'SYS_kill',
            39: 'SYS_getppid',
            41: 'SYS_dup',
            42: 'SYS_pipe',
            43: 'SYS_getegid',
            46: 'SYS_sigaction',
            47: 'SYS_getgid',
            48: 'SYS_sigprocmask',
            49: 'SYS_getlogin',
            50: 'SYS_setlogin',
            51: 'SYS_acct',
            52: 'SYS_sigpending',
            53: 'SYS_sigaltstack',
            54: 'SYS_ioctl',
            55: 'SYS_reboot',
            56: 'SYS_revoke',
            57: 'SYS_symlink',
            58: 'SYS_readlink',
            59: 'SYS_execve',
            60: 'SYS_umask',
            61: 'SYS_chroot',
            63: 'SYS_invalid',
            65: 'SYS_msync',
            66: 'SYS_vfork',
            73: 'SYS_munmap',
            74: 'SYS_mprotect',
            75: 'SYS_madvise',
            78: 'SYS_mincore',
            79: 'SYS_getgroups',
            80: 'SYS_setgroups',
            81: 'SYS_getpgrp',
            82: 'SYS_setpgid',
            83: 'SYS_setitimer',
            85: 'SYS_swapon',
            86: 'SYS_getitimer',
            89: 'SYS_getdtablesize',
            90: 'SYS_dup2',
            92: 'SYS_fcntl',
            93: 'SYS_select',
            95: 'SYS_fsync',
            96: 'SYS_setpriority',
            97: 'SYS_socket',
            98: 'SYS_connect',
            100: 'SYS_getpriority',
            104: 'SYS_bind',
            105: 'SYS_setsockopt',
            106: 'SYS_listen',
            111: 'SYS_sigsuspend',
            116: 'SYS_gettimeofday',
            117: 'SYS_getrusage',
            118: 'SYS_getsockopt',
            120: 'SYS_readv',
            121: 'SYS_writev',
            122: 'SYS_settimeofday',
            123: 'SYS_fchown',
            124: 'SYS_fchmod',
            126: 'SYS_setreuid',
            127: 'SYS_setregid',
            128: 'SYS_rename',
            131: 'SYS_flock',
            132: 'SYS_mkfifo',
            133: 'SYS_sendto',
            134: 'SYS_shutdown',
            135: 'SYS_socketpair',
            136: 'SYS_mkdir',
            137: 'SYS_rmdir',
            138: 'SYS_utimes',
            139: 'SYS_futimes',
            140: 'SYS_adjtime',
            142: 'SYS_gethostuuid',
            147: 'SYS_setsid',
            151: 'SYS_getpgid',
            152: 'SYS_setprivexec',
            153: 'SYS_pread',
            154: 'SYS_pwrite',
            155: 'SYS_nfssvc',
            157: 'SYS_statfs',
            158: 'SYS_fstatfs',
            159: 'SYS_unmount',
            161: 'SYS_getfh',
            165: 'SYS_quotactl',
            167: 'SYS_mount',
            169: 'SYS_csops',
            170: 'SYS_csops_audittoken',
            173: 'SYS_waitid',
            177: 'SYS_kdebug_typefilter',
            178: 'SYS_kdebug_trace_string',
            179: 'SYS_kdebug_trace64',
            180: 'SYS_kdebug_trace',
            181: 'SYS_setgid',
            182: 'SYS_setegid',
            183: 'SYS_seteuid',
            184: 'SYS_sigreturn',
            186: 'SYS_thread_selfcounts',
            187: 'SYS_fdatasync',
            188: 'SYS_stat',
            189: 'SYS_fstat',
            190: 'SYS_lstat',
            191: 'SYS_pathconf',
            192: 'SYS_fpathconf',
            194: 'SYS_getrlimit',
            195: 'SYS_setrlimit',
            196: 'SYS_getdirentries',
            197: 'SYS_mmap',
            199: 'SYS_lseek',
            200: 'SYS_truncate',
            201: 'SYS_ftruncate',
            202: 'SYS_sysctl',
            203: 'SYS_mlock',
            204: 'SYS_munlock',
            205: 'SYS_undelete',
            216: 'SYS_open_dprotected_np',
            217: 'SYS_fsgetpath_ext',
            218: 'SYS_openat_dprotected_np',
            220: 'SYS_getattrlist',
            221: 'SYS_setattrlist',
            222: 'SYS_getdirentriesattr',
            223: 'SYS_exchangedata',
            225: 'SYS_searchfs',
            226: 'SYS_delete',
            227: 'SYS_copyfile',
            228: 'SYS_fgetattrlist',
            229: 'SYS_fsetattrlist',
            230: 'SYS_poll',
            234: 'SYS_getxattr',
            235: 'SYS_fgetxattr',
            236: 'SYS_setxattr',
            237: 'SYS_fsetxattr',
            238: 'SYS_removexattr',
            239: 'SYS_fremovexattr',
            240: 'SYS_listxattr',
            241: 'SYS_flistxattr',
            242: 'SYS_fsctl',
            243: 'SYS_initgroups',
            244: 'SYS_posix_spawn',
            245: 'SYS_ffsctl',
            248: 'SYS_fhopen',
            250: 'SYS_minherit',
            251: 'SYS_semsys',
            252: 'SYS_msgsys',
            253: 'SYS_shmsys',
            254: 'SYS_semctl',
            255: 'SYS_semget',
            256: 'SYS_semop',
            258: 'SYS_msgctl',
            259: 'SYS_msgget',
            260: 'SYS_msgsnd',
            261: 'SYS_msgrcv',
            262: 'SYS_shmat',
            263: 'SYS_shmctl',
            264: 'SYS_shmdt',
            265: 'SYS_shmget',
            266: 'SYS_shm_open',
            267: 'SYS_shm_unlink',
            268: 'SYS_sem_open',
            269: 'SYS_sem_close',
            270: 'SYS_sem_unlink',
            271: 'SYS_sem_wait',
            272: 'SYS_sem_trywait',
            273: 'SYS_sem_post',
            274: 'SYS_sysctlbyname',
            277: 'SYS_open_extended',
            278: 'SYS_umask_extended',
            279: 'SYS_stat_extended',
            280: 'SYS_lstat_extended',
            281: 'SYS_fstat_extended',
            282: 'SYS_chmod_extended',
            283: 'SYS_fchmod_extended',
            284: 'SYS_access_extended',
            285: 'SYS_settid',
            286: 'SYS_gettid',
            287: 'SYS_setsgroups',
            288: 'SYS_getsgroups',
            289: 'SYS_setwgroups',
            290: 'SYS_getwgroups',
            291: 'SYS_mkfifo_extended',
            292: 'SYS_mkdir_extended',
            293: 'SYS_identitysvc',
            294: 'SYS_shared_region_check_np',
            296: 'SYS_vm_pressure_monitor',
            297: 'SYS_psynch_rw_longrdlock',
            298: 'SYS_psynch_rw_yieldwrlock',
            299: 'SYS_psynch_rw_downgrade',
            300: 'SYS_psynch_rw_upgrade',
            301: 'SYS_psynch_mutexwait',
            302: 'SYS_psynch_mutexdrop',
            303: 'SYS_psynch_cvbroad',
            304: 'SYS_psynch_cvsignal',
            305: 'SYS_psynch_cvwait',
            306: 'SYS_psynch_rw_rdlock',
            307: 'SYS_psynch_rw_wrlock',
            308: 'SYS_psynch_rw_unlock',
            309: 'SYS_psynch_rw_unlock2',
            310: 'SYS_getsid',
            311: 'SYS_settid_with_pid',
            312: 'SYS_psynch_cvclrprepost',
            313: 'SYS_aio_fsync',
            314: 'SYS_aio_return',
            315: 'SYS_aio_suspend',
            316: 'SYS_aio_cancel',
            317: 'SYS_aio_error',
            318: 'SYS_aio_read',
            319: 'SYS_aio_write',
            320: 'SYS_lio_listio',
            322: 'SYS_iopolicysys',
            323: 'SYS_process_policy',
            324: 'SYS_mlockall',
            325: 'SYS_munlockall',
            327: 'SYS_issetugid',
            328: 'SYS___pthread_kill',
            329: 'SYS___pthread_sigmask',
            330: 'SYS___sigwait',
            331: 'SYS___disable_threadsignal',
            332: 'SYS___pthread_markcancel',
            333: 'SYS___pthread_canceled',
            334: 'SYS___semwait_signal',
            336: 'SYS_proc_info',
            337: 'SYS_sendfile',
            338: 'SYS_stat64',
            339: 'SYS_fstat64',
            340: 'SYS_lstat64',
            341: 'SYS_stat64_extended',
            342: 'SYS_lstat64_extended',
            343: 'SYS_fstat64_extended',
            344: 'SYS_getdirentries64',
            345: 'SYS_statfs64',
            346: 'SYS_fstatfs64',
            347: 'SYS_getfsstat64',
            348: 'SYS___pthread_chdir',
            349: 'SYS___pthread_fchdir',
            350: 'SYS_audit',
            351: 'SYS_auditon',
            353: 'SYS_getauid',
            354: 'SYS_setauid',
            357: 'SYS_getaudit_addr',
            358: 'SYS_setaudit_addr',
            359: 'SYS_auditctl',
            360: 'SYS_bsdthread_create',
            361: 'SYS_bsdthread_terminate',
            362: 'SYS_kqueue',
            363: 'SYS_kevent',
            364: 'SYS_lchown',
            366: 'SYS_bsdthread_register',
            367: 'SYS_workq_open',
            368: 'SYS_workq_kernreturn',
            369: 'SYS_kevent64',
            372: 'SYS_thread_selfid',
            373: 'SYS_ledger',
            374: 'SYS_kevent_qos',
            375: 'SYS_kevent_id',
            380: 'SYS___mac_execve',
            381: 'SYS___mac_syscall',
            382: 'SYS___mac_get_file',
            383: 'SYS___mac_set_file',
            384: 'SYS___mac_get_link',
            385: 'SYS___mac_set_link',
            386: 'SYS___mac_get_proc',
            387: 'SYS___mac_set_proc',
            388: 'SYS___mac_get_fd',
            389: 'SYS___mac_set_fd',
            390: 'SYS___mac_get_pid',
            394: 'SYS_pselect',
            395: 'SYS_pselect_nocancel',
            396: 'SYS_read_nocancel',
            397: 'SYS_write_nocancel',
            398: 'SYS_open_nocancel',
            399: 'SYS_close_nocancel',
            400: 'SYS_wait4_nocancel',
            401: 'SYS_recvmsg_nocancel',
            402: 'SYS_sendmsg_nocancel',
            403: 'SYS_recvfrom_nocancel',
            404: 'SYS_accept_nocancel',
            405: 'SYS_msync_nocancel',
            406: 'SYS_fcntl_nocancel',
            407: 'SYS_select_nocancel',
            408: 'SYS_fsync_nocancel',
            409: 'SYS_connect_nocancel',
            410: 'SYS_sigsuspend_nocancel',
            411: 'SYS_readv_nocancel',
            412: 'SYS_writev_nocancel',
            413: 'SYS_sendto_nocancel',
            414: 'SYS_pread_nocancel',
            415: 'SYS_pwrite_nocancel',
            416: 'SYS_waitid_nocancel',
            417: 'SYS_poll_nocancel',
            418: 'SYS_msgsnd_nocancel',
            419: 'SYS_msgrcv_nocancel',
            420: 'SYS_sem_wait_nocancel',
            421: 'SYS_aio_suspend_nocancel',
            422: 'SYS___sigwait_nocancel',
            423: 'SYS___semwait_signal_nocancel',
            424: 'SYS___mac_mount',
            425: 'SYS___mac_get_mount',
            426: 'SYS___mac_getfsstat',
            427: 'SYS_fsgetpath',
            428: 'SYS_audit_session_self',
            429: 'SYS_audit_session_join',
            430: 'SYS_fileport_makeport',
            431: 'SYS_fileport_makefd',
            432: 'SYS_audit_session_port',
            433: 'SYS_pid_suspend',
            434: 'SYS_pid_resume',
            435: 'SYS_pid_hibernate',
            436: 'SYS_pid_shutdown_sockets',
            439: 'SYS_kas_info',
            440: 'SYS_memorystatus_control',
            441: 'SYS_guarded_open_np',
            442: 'SYS_guarded_close_np',
            443: 'SYS_guarded_kqueue_np',
            444: 'SYS_change_fdguard_np',
            445: 'SYS_usrctl',
            446: 'SYS_proc_rlimit_control',
            447: 'SYS_connectx',
            448: 'SYS_disconnectx',
            449: 'SYS_peeloff',
            450: 'SYS_socket_delegate',
            451: 'SYS_telemetry',
            452: 'SYS_proc_uuid_policy',
            453: 'SYS_memorystatus_get_level',
            454: 'SYS_system_override',
            455: 'SYS_vfs_purge',
            456: 'SYS_sfi_ctl',
            457: 'SYS_sfi_pidctl',
            458: 'SYS_coalition',
            459: 'SYS_coalition_info',
            460: 'SYS_necp_match_policy',
            461: 'SYS_getattrlistbulk',
            462: 'SYS_clonefileat',
            463: 'SYS_openat',
            464: 'SYS_openat_nocancel',
            465: 'SYS_renameat',
            466: 'SYS_faccessat',
            467: 'SYS_fchmodat',
            468: 'SYS_fchownat',
            469: 'SYS_fstatat',
            470: 'SYS_fstatat64',
            471: 'SYS_linkat',
            472: 'SYS_unlinkat',
            473: 'SYS_readlinkat',
            474: 'SYS_symlinkat',
            475: 'SYS_mkdirat',
            476: 'SYS_getattrlistat',
            477: 'SYS_proc_trace_log',
            478: 'SYS_bsdthread_ctl',
            479: 'SYS_openbyid_np',
            480: 'SYS_recvmsg_x',
            481: 'SYS_sendmsg_x',
            482: 'SYS_thread_selfusage',
            483: 'SYS_csrctl',
            484: 'SYS_guarded_open_dprotected_np',
            485: 'SYS_guarded_write_np',
            486: 'SYS_guarded_pwrite_np',
            487: 'SYS_guarded_writev_np',
            488: 'SYS_renameatx_np',
            489: 'SYS_mremap_encrypted',
            490: 'SYS_netagent_trigger',
            491: 'SYS_stack_snapshot_with_config',
            492: 'SYS_microstackshot',
            493: 'SYS_grab_pgo_data',
            494: 'SYS_persona',
            496: 'SYS_mach_eventlink_signal',
            497: 'SYS_mach_eventlink_wait_until',
            498: 'SYS_mach_eventlink_signal_wait_until',
            499: 'SYS_work_interval_ctl',
            500: 'SYS_getentropy',
            501: 'SYS_necp_open',
            502: 'SYS_necp_client_action',
            503: 'SYS___nexus_open',
            504: 'SYS___nexus_register',
            505: 'SYS___nexus_deregister',
            506: 'SYS___nexus_create',
            507: 'SYS___nexus_destroy',
            508: 'SYS___nexus_get_opt',
            509: 'SYS___nexus_set_opt',
            510: 'SYS___channel_open',
            511: 'SYS___channel_get_info',
            512: 'SYS___channel_sync',
            513: 'SYS___channel_get_opt',
            514: 'SYS___channel_set_opt',
            515: 'SYS_ulock_wait',
            516: 'SYS_ulock_wake',
            517: 'SYS_fclonefileat',
            518: 'SYS_fs_snapshot',
            519: 'SYS_register_uexc_handler',
            520: 'SYS_terminate_with_payload',
            521: 'SYS_abort_with_payload',
            522: 'SYS_necp_session_open',
            523: 'SYS_necp_session_action',
            524: 'SYS_setattrlistat',
            525: 'SYS_net_qos_guideline',
            526: 'SYS_fmount',
            527: 'SYS_ntp_adjtime',
            528: 'SYS_ntp_gettime',
            529: 'SYS_os_fault_with_payload',
            530: 'SYS_kqueue_workloop_ctl',
            531: 'SYS___mach_bridge_remote_time',
            532: 'SYS_coalition_ledger',
            533: 'SYS_log_data',
            534: 'SYS_memorystatus_available_memory',
            535: 'SYS_objc_bp_assist_cfg_np',
            536: 'SYS_shared_region_map_and_slide_2_np',
            537: 'SYS_pivot_root',
            538: 'SYS_task_inspect_for_pid',
            539: 'SYS_task_read_for_pid',
            540: 'SYS_preadv',
            541: 'SYS_pwritev',
            542: 'SYS_preadv_nocancel',
            543: 'SYS_pwritev_nocancel',
            544: 'SYS_ulock_wait2',
            545: 'SYS_proc_info_extended_id',
            546: 'SYS_tracker_action',
            547: 'SYS_debug_syscall_reject',
            548: 'SYS_debug_syscall_reject_config',
            549: 'SYS_graftdmg',
            550: 'SYS_map_with_linking_np',
            551: 'SYS_freadlink',
            552: 'SYS_record_system_event',
            553: 'SYS_mkfifoat',
            554: 'SYS_mknodat',
            555: 'SYS_ungraftdmg'}
    if arg in arg_types.keys():
        return '%s' % (arg_types[arg])
    else:
        return '%d' % arg

def get_filter_arg_syscall_mach_number_bitmask(f, offset):

    global keep_builtin_filters
    global base_addr

    f.seek(offset * 8 + base_addr)
    might_be_type = struct.unpack("<H", f.read(2))[0]
    bitmap_length = struct.unpack("<H", f.read(2))[0]
    bitmap = f.read(bitmap_length)

    enabled_syscalls = []
    for byte_index, byte in enumerate(bitmap):
        for bit_position in range(0, 8, 2):
            mask = (byte >> bit_position) & 0b11
            if mask:
                syscall_number = (byte_index * 8) + mask
                syscall_name = f"syscall_mach_number_{syscall_number}"
                enabled_syscalls.append(syscall_name)

def get_filter_arg_mac_syscall_number_bitmask(f, offset):

    global keep_builtin_filters
    global base_addr

    f.seek(offset * 8 + base_addr)
    might_be_type = struct.unpack("<H", f.read(2))[0]
    bitmap_length = struct.unpack("<H", f.read(2))[0]
    bitmap = f.read(bitmap_length)

    enabled_syscalls = []
    for byte_index, byte in enumerate(bitmap):
        for bit_position in range(0, 8, 2):
            mask = (byte >> bit_position) & 0b11
            if mask:
                syscall_number = (byte_index * 8) + mask
                syscall_name = f"mac_syscall_number_{syscall_number}"
                enabled_syscalls.append(syscall_name)
    return " | ".join(enabled_syscalls)

def get_filter_arg_syscall_number_bitmask(f, offset):
    """Convert integer to syscall number type string."""
    global keep_builtin_filters
    global base_addr

    arg_types = {
            0: 'SYS_syscall',
            1: 'SYS_exit',
            2: 'SYS_fork',
            3: 'SYS_read',
            4: 'SYS_write',
            5: 'SYS_open',
            8: 'PERSONA_ENTERPRISE',
            6: 'SYS_close',
            7: 'SYS_wait4',
            9: 'SYS_link',
            10: 'SYS_unlink',
            12: 'SYS_chdir',
            13: 'SYS_fchdir',
            14: 'SYS_mknod',
            15: 'SYS_chmod',
            16: 'SYS_chown',
            18: 'SYS_getfsstat',
            20: 'SYS_getpid',
            23: 'SYS_setuid',
            24: 'SYS_getuid',
            25: 'SYS_geteuid',
            26: 'SYS_ptrace',
            27: 'SYS_recvmsg',
            28: 'SYS_sendmsg',
            29: 'SYS_recvfrom',
            30: 'SYS_accept',
            31: 'SYS_getpeername',
            32: 'SYS_getsockname',
            33: 'SYS_access',
            34: 'SYS_chflags',
            35: 'SYS_fchflags',
            36: 'SYS_sync',
            37: 'SYS_kill',
            39: 'SYS_getppid',
            41: 'SYS_dup',
            42: 'SYS_pipe',
            43: 'SYS_getegid',
            46: 'SYS_sigaction',
            47: 'SYS_getgid',
            48: 'SYS_sigprocmask',
            49: 'SYS_getlogin',
            50: 'SYS_setlogin',
            51: 'SYS_acct',
            52: 'SYS_sigpending',
            53: 'SYS_sigaltstack',
            54: 'SYS_ioctl',
            55: 'SYS_reboot',
            56: 'SYS_revoke',
            57: 'SYS_symlink',
            58: 'SYS_readlink',
            59: 'SYS_execve',
            60: 'SYS_umask',
            61: 'SYS_chroot',
            63: 'SYS_invalid',
            65: 'SYS_msync',
            66: 'SYS_vfork',
            73: 'SYS_munmap',
            74: 'SYS_mprotect',
            75: 'SYS_madvise',
            78: 'SYS_mincore',
            79: 'SYS_getgroups',
            80: 'SYS_setgroups',
            81: 'SYS_getpgrp',
            82: 'SYS_setpgid',
            83: 'SYS_setitimer',
            85: 'SYS_swapon',
            86: 'SYS_getitimer',
            89: 'SYS_getdtablesize',
            90: 'SYS_dup2',
            92: 'SYS_fcntl',
            93: 'SYS_select',
            95: 'SYS_fsync',
            96: 'SYS_setpriority',
            97: 'SYS_socket',
            98: 'SYS_connect',
            100: 'SYS_getpriority',
            104: 'SYS_bind',
            105: 'SYS_setsockopt',
            106: 'SYS_listen',
            111: 'SYS_sigsuspend',
            116: 'SYS_gettimeofday',
            117: 'SYS_getrusage',
            118: 'SYS_getsockopt',
            120: 'SYS_readv',
            121: 'SYS_writev',
            122: 'SYS_settimeofday',
            123: 'SYS_fchown',
            124: 'SYS_fchmod',
            126: 'SYS_setreuid',
            127: 'SYS_setregid',
            128: 'SYS_rename',
            131: 'SYS_flock',
            132: 'SYS_mkfifo',
            133: 'SYS_sendto',
            134: 'SYS_shutdown',
            135: 'SYS_socketpair',
            136: 'SYS_mkdir',
            137: 'SYS_rmdir',
            138: 'SYS_utimes',
            139: 'SYS_futimes',
            140: 'SYS_adjtime',
            142: 'SYS_gethostuuid',
            147: 'SYS_setsid',
            151: 'SYS_getpgid',
            152: 'SYS_setprivexec',
            153: 'SYS_pread',
            154: 'SYS_pwrite',
            155: 'SYS_nfssvc',
            157: 'SYS_statfs',
            158: 'SYS_fstatfs',
            159: 'SYS_unmount',
            161: 'SYS_getfh',
            165: 'SYS_quotactl',
            167: 'SYS_mount',
            169: 'SYS_csops',
            170: 'SYS_csops_audittoken',
            173: 'SYS_waitid',
            177: 'SYS_kdebug_typefilter',
            178: 'SYS_kdebug_trace_string',
            179: 'SYS_kdebug_trace64',
            180: 'SYS_kdebug_trace',
            181: 'SYS_setgid',
            182: 'SYS_setegid',
            183: 'SYS_seteuid',
            184: 'SYS_sigreturn',
            186: 'SYS_thread_selfcounts',
            187: 'SYS_fdatasync',
            188: 'SYS_stat',
            189: 'SYS_fstat',
            190: 'SYS_lstat',
            191: 'SYS_pathconf',
            192: 'SYS_fpathconf',
            194: 'SYS_getrlimit',
            195: 'SYS_setrlimit',
            196: 'SYS_getdirentries',
            197: 'SYS_mmap',
            199: 'SYS_lseek',
            200: 'SYS_truncate',
            201: 'SYS_ftruncate',
            202: 'SYS_sysctl',
            203: 'SYS_mlock',
            204: 'SYS_munlock',
            205: 'SYS_undelete',
            216: 'SYS_open_dprotected_np',
            217: 'SYS_fsgetpath_ext',
            218: 'SYS_openat_dprotected_np',
            220: 'SYS_getattrlist',
            221: 'SYS_setattrlist',
            222: 'SYS_getdirentriesattr',
            223: 'SYS_exchangedata',
            225: 'SYS_searchfs',
            226: 'SYS_delete',
            227: 'SYS_copyfile',
            228: 'SYS_fgetattrlist',
            229: 'SYS_fsetattrlist',
            230: 'SYS_poll',
            234: 'SYS_getxattr',
            235: 'SYS_fgetxattr',
            236: 'SYS_setxattr',
            237: 'SYS_fsetxattr',
            238: 'SYS_removexattr',
            239: 'SYS_fremovexattr',
            240: 'SYS_listxattr',
            241: 'SYS_flistxattr',
            242: 'SYS_fsctl',
            243: 'SYS_initgroups',
            244: 'SYS_posix_spawn',
            245: 'SYS_ffsctl',
            248: 'SYS_fhopen',
            250: 'SYS_minherit',
            251: 'SYS_semsys',
            252: 'SYS_msgsys',
            253: 'SYS_shmsys',
            254: 'SYS_semctl',
            255: 'SYS_semget',
            256: 'SYS_semop',
            258: 'SYS_msgctl',
            259: 'SYS_msgget',
            260: 'SYS_msgsnd',
            261: 'SYS_msgrcv',
            262: 'SYS_shmat',
            263: 'SYS_shmctl',
            264: 'SYS_shmdt',
            265: 'SYS_shmget',
            266: 'SYS_shm_open',
            267: 'SYS_shm_unlink',
            268: 'SYS_sem_open',
            269: 'SYS_sem_close',
            270: 'SYS_sem_unlink',
            271: 'SYS_sem_wait',
            272: 'SYS_sem_trywait',
            273: 'SYS_sem_post',
            274: 'SYS_sysctlbyname',
            277: 'SYS_open_extended',
            278: 'SYS_umask_extended',
            279: 'SYS_stat_extended',
            280: 'SYS_lstat_extended',
            281: 'SYS_fstat_extended',
            282: 'SYS_chmod_extended',
            283: 'SYS_fchmod_extended',
            284: 'SYS_access_extended',
            285: 'SYS_settid',
            286: 'SYS_gettid',
            287: 'SYS_setsgroups',
            288: 'SYS_getsgroups',
            289: 'SYS_setwgroups',
            290: 'SYS_getwgroups',
            291: 'SYS_mkfifo_extended',
            292: 'SYS_mkdir_extended',
            293: 'SYS_identitysvc',
            294: 'SYS_shared_region_check_np',
            296: 'SYS_vm_pressure_monitor',
            297: 'SYS_psynch_rw_longrdlock',
            298: 'SYS_psynch_rw_yieldwrlock',
            299: 'SYS_psynch_rw_downgrade',
            300: 'SYS_psynch_rw_upgrade',
            301: 'SYS_psynch_mutexwait',
            302: 'SYS_psynch_mutexdrop',
            303: 'SYS_psynch_cvbroad',
            304: 'SYS_psynch_cvsignal',
            305: 'SYS_psynch_cvwait',
            306: 'SYS_psynch_rw_rdlock',
            307: 'SYS_psynch_rw_wrlock',
            308: 'SYS_psynch_rw_unlock',
            309: 'SYS_psynch_rw_unlock2',
            310: 'SYS_getsid',
            311: 'SYS_settid_with_pid',
            312: 'SYS_psynch_cvclrprepost',
            313: 'SYS_aio_fsync',
            314: 'SYS_aio_return',
            315: 'SYS_aio_suspend',
            316: 'SYS_aio_cancel',
            317: 'SYS_aio_error',
            318: 'SYS_aio_read',
            319: 'SYS_aio_write',
            320: 'SYS_lio_listio',
            322: 'SYS_iopolicysys',
            323: 'SYS_process_policy',
            324: 'SYS_mlockall',
            325: 'SYS_munlockall',
            327: 'SYS_issetugid',
            328: 'SYS___pthread_kill',
            329: 'SYS___pthread_sigmask',
            330: 'SYS___sigwait',
            331: 'SYS___disable_threadsignal',
            332: 'SYS___pthread_markcancel',
            333: 'SYS___pthread_canceled',
            334: 'SYS___semwait_signal',
            336: 'SYS_proc_info',
            337: 'SYS_sendfile',
            338: 'SYS_stat64',
            339: 'SYS_fstat64',
            340: 'SYS_lstat64',
            341: 'SYS_stat64_extended',
            342: 'SYS_lstat64_extended',
            343: 'SYS_fstat64_extended',
            344: 'SYS_getdirentries64',
            345: 'SYS_statfs64',
            346: 'SYS_fstatfs64',
            347: 'SYS_getfsstat64',
            348: 'SYS___pthread_chdir',
            349: 'SYS___pthread_fchdir',
            350: 'SYS_audit',
            351: 'SYS_auditon',
            353: 'SYS_getauid',
            354: 'SYS_setauid',
            357: 'SYS_getaudit_addr',
            358: 'SYS_setaudit_addr',
            359: 'SYS_auditctl',
            360: 'SYS_bsdthread_create',
            361: 'SYS_bsdthread_terminate',
            362: 'SYS_kqueue',
            363: 'SYS_kevent',
            364: 'SYS_lchown',
            366: 'SYS_bsdthread_register',
            367: 'SYS_workq_open',
            368: 'SYS_workq_kernreturn',
            369: 'SYS_kevent64',
            372: 'SYS_thread_selfid',
            373: 'SYS_ledger',
            374: 'SYS_kevent_qos',
            375: 'SYS_kevent_id',
            380: 'SYS___mac_execve',
            381: 'SYS___mac_syscall',
            382: 'SYS___mac_get_file',
            383: 'SYS___mac_set_file',
            384: 'SYS___mac_get_link',
            385: 'SYS___mac_set_link',
            386: 'SYS___mac_get_proc',
            387: 'SYS___mac_set_proc',
            388: 'SYS___mac_get_fd',
            389: 'SYS___mac_set_fd',
            390: 'SYS___mac_get_pid',
            394: 'SYS_pselect',
            395: 'SYS_pselect_nocancel',
            396: 'SYS_read_nocancel',
            397: 'SYS_write_nocancel',
            398: 'SYS_open_nocancel',
            399: 'SYS_close_nocancel',
            400: 'SYS_wait4_nocancel',
            401: 'SYS_recvmsg_nocancel',
            402: 'SYS_sendmsg_nocancel',
            403: 'SYS_recvfrom_nocancel',
            404: 'SYS_accept_nocancel',
            405: 'SYS_msync_nocancel',
            406: 'SYS_fcntl_nocancel',
            407: 'SYS_select_nocancel',
            408: 'SYS_fsync_nocancel',
            409: 'SYS_connect_nocancel',
            410: 'SYS_sigsuspend_nocancel',
            411: 'SYS_readv_nocancel',
            412: 'SYS_writev_nocancel',
            413: 'SYS_sendto_nocancel',
            414: 'SYS_pread_nocancel',
            415: 'SYS_pwrite_nocancel',
            416: 'SYS_waitid_nocancel',
            417: 'SYS_poll_nocancel',
            418: 'SYS_msgsnd_nocancel',
            419: 'SYS_msgrcv_nocancel',
            420: 'SYS_sem_wait_nocancel',
            421: 'SYS_aio_suspend_nocancel',
            422: 'SYS___sigwait_nocancel',
            423: 'SYS___semwait_signal_nocancel',
            424: 'SYS___mac_mount',
            425: 'SYS___mac_get_mount',
            426: 'SYS___mac_getfsstat',
            427: 'SYS_fsgetpath',
            428: 'SYS_audit_session_self',
            429: 'SYS_audit_session_join',
            430: 'SYS_fileport_makeport',
            431: 'SYS_fileport_makefd',
            432: 'SYS_audit_session_port',
            433: 'SYS_pid_suspend',
            434: 'SYS_pid_resume',
            435: 'SYS_pid_hibernate',
            436: 'SYS_pid_shutdown_sockets',
            439: 'SYS_kas_info',
            440: 'SYS_memorystatus_control',
            441: 'SYS_guarded_open_np',
            442: 'SYS_guarded_close_np',
            443: 'SYS_guarded_kqueue_np',
            444: 'SYS_change_fdguard_np',
            445: 'SYS_usrctl',
            446: 'SYS_proc_rlimit_control',
            447: 'SYS_connectx',
            448: 'SYS_disconnectx',
            449: 'SYS_peeloff',
            450: 'SYS_socket_delegate',
            451: 'SYS_telemetry',
            452: 'SYS_proc_uuid_policy',
            453: 'SYS_memorystatus_get_level',
            454: 'SYS_system_override',
            455: 'SYS_vfs_purge',
            456: 'SYS_sfi_ctl',
            457: 'SYS_sfi_pidctl',
            458: 'SYS_coalition',
            459: 'SYS_coalition_info',
            460: 'SYS_necp_match_policy',
            461: 'SYS_getattrlistbulk',
            462: 'SYS_clonefileat',
            463: 'SYS_openat',
            464: 'SYS_openat_nocancel',
            465: 'SYS_renameat',
            466: 'SYS_faccessat',
            467: 'SYS_fchmodat',
            468: 'SYS_fchownat',
            469: 'SYS_fstatat',
            470: 'SYS_fstatat64',
            471: 'SYS_linkat',
            472: 'SYS_unlinkat',
            473: 'SYS_readlinkat',
            474: 'SYS_symlinkat',
            475: 'SYS_mkdirat',
            476: 'SYS_getattrlistat',
            477: 'SYS_proc_trace_log',
            478: 'SYS_bsdthread_ctl',
            479: 'SYS_openbyid_np',
            480: 'SYS_recvmsg_x',
            481: 'SYS_sendmsg_x',
            482: 'SYS_thread_selfusage',
            483: 'SYS_csrctl',
            484: 'SYS_guarded_open_dprotected_np',
            485: 'SYS_guarded_write_np',
            486: 'SYS_guarded_pwrite_np',
            487: 'SYS_guarded_writev_np',
            488: 'SYS_renameatx_np',
            489: 'SYS_mremap_encrypted',
            490: 'SYS_netagent_trigger',
            491: 'SYS_stack_snapshot_with_config',
            492: 'SYS_microstackshot',
            493: 'SYS_grab_pgo_data',
            494: 'SYS_persona',
            496: 'SYS_mach_eventlink_signal',
            497: 'SYS_mach_eventlink_wait_until',
            498: 'SYS_mach_eventlink_signal_wait_until',
            499: 'SYS_work_interval_ctl',
            500: 'SYS_getentropy',
            501: 'SYS_necp_open',
            502: 'SYS_necp_client_action',
            503: 'SYS___nexus_open',
            504: 'SYS___nexus_register',
            505: 'SYS___nexus_deregister',
            506: 'SYS___nexus_create',
            507: 'SYS___nexus_destroy',
            508: 'SYS___nexus_get_opt',
            509: 'SYS___nexus_set_opt',
            510: 'SYS___channel_open',
            511: 'SYS___channel_get_info',
            512: 'SYS___channel_sync',
            513: 'SYS___channel_get_opt',
            514: 'SYS___channel_set_opt',
            515: 'SYS_ulock_wait',
            516: 'SYS_ulock_wake',
            517: 'SYS_fclonefileat',
            518: 'SYS_fs_snapshot',
            519: 'SYS_register_uexc_handler',
            520: 'SYS_terminate_with_payload',
            521: 'SYS_abort_with_payload',
            522: 'SYS_necp_session_open',
            523: 'SYS_necp_session_action',
            524: 'SYS_setattrlistat',
            525: 'SYS_net_qos_guideline',
            526: 'SYS_fmount',
            527: 'SYS_ntp_adjtime',
            528: 'SYS_ntp_gettime',
            529: 'SYS_os_fault_with_payload',
            530: 'SYS_kqueue_workloop_ctl',
            531: 'SYS___mach_bridge_remote_time',
            532: 'SYS_coalition_ledger',
            533: 'SYS_log_data',
            534: 'SYS_memorystatus_available_memory',
            535: 'SYS_objc_bp_assist_cfg_np',
            536: 'SYS_shared_region_map_and_slide_2_np',
            537: 'SYS_pivot_root',
            538: 'SYS_task_inspect_for_pid',
            539: 'SYS_task_read_for_pid',
            540: 'SYS_preadv',
            541: 'SYS_pwritev',
            542: 'SYS_preadv_nocancel',
            543: 'SYS_pwritev_nocancel',
            544: 'SYS_ulock_wait2',
            545: 'SYS_proc_info_extended_id',
            546: 'SYS_tracker_action',
            547: 'SYS_debug_syscall_reject',
            548: 'SYS_debug_syscall_reject_config',
            549: 'SYS_graftdmg',
            550: 'SYS_map_with_linking_np',
            551: 'SYS_freadlink',
            552: 'SYS_record_system_event',
            553: 'SYS_mkfifoat',
            554: 'SYS_mknodat',
            555: 'SYS_ungraftdmg'}

    f.seek(offset * 8 + base_addr)
    might_be_type = struct.unpack("<H", f.read(2))[0]
    bitmap_length = struct.unpack("<H", f.read(2))[0]
    bitmap = f.read(bitmap_length)

    enabled_syscalls = []
    for byte_index, byte in enumerate(bitmap):
        for bit_position in range(0, 8, 2):
            mask = (byte >> bit_position) & 0b11
            if mask:
                syscall_number = (byte_index * 8) + mask
                syscall_name = arg_types.get(syscall_number, f"UNKNOWN_syscall_number_{syscall_number}")
                enabled_syscalls.append(syscall_name)

    return " | ".join(enabled_syscalls)

def get_filter_arg_entry_attribute(f, arg):
    """Convert integer to entry attribute type string."""
    arg_types = {
            0: 'ioservice-requires-approval',
            }
    if arg in arg_types.keys():
        return '%s' % (arg_types[arg])
    else:
        return '%d' % arg


def get_filter_arg_machtrap_bitmask(f, offset):
    arg_types = {
        10: 'MSC__kernelrpc_mach_vm_allocate_trap',
        11: 'MSC__kernelrpc_mach_vm_purgable_control_trap',
        12: 'MSC__kernelrpc_mach_vm_deallocate_trap',
        13: 'MSC_task_dyld_process_info_notify_get',
        14: 'MSC__kernelrpc_mach_vm_protect_trap',
        15: 'MSC__kernelrpc_mach_vm_map_trap',
        16: 'MSC__kernelrpc_mach_port_allocate_trap',
        18: 'MSC__kernelrpc_mach_port_deallocate_trap',
        19: 'MSC__kernelrpc_mach_port_mod_refs_trap',
        20: 'MSC__kernelrpc_mach_port_move_member_trap',
        21: 'MSC__kernelrpc_mach_port_insert_right_trap',
        22: 'MSC__kernelrpc_mach_port_insert_member_trap',
        23: 'MSC__kernelrpc_mach_port_extract_member_trap',
        24: 'MSC__kernelrpc_mach_port_construct_trap',
        25: 'MSC__kernelrpc_mach_port_destruct_trap',
        26: 'MSC_mach_reply_port',
        27: 'MSC_thread_self_trap',
        28: 'MSC_task_self_trap',
        29: 'MSC_host_self_trap',
        31: 'MSC_mach_msg_trap',
        32: 'MSC_mach_msg_overwrite_trap',
        33: 'MSC_semaphore_signal_trap',
        34: 'MSC_semaphore_signal_all_trap',
        35: 'MSC_semaphore_signal_thread_trap',
        36: 'MSC_semaphore_wait_trap',
        37: 'MSC_semaphore_wait_signal_trap',
        38: 'MSC_semaphore_timedwait_trap',
        39: 'MSC_semaphore_timedwait_signal_trap',
        40: 'MSC__kernelrpc_mach_port_get_attributes_trap',
        41: 'MSC__kernelrpc_mach_port_guard_trap',
        42: 'MSC__kernelrpc_mach_port_unguard_trap',
        43: 'MSC_mach_generate_activity_id',
        44: 'MSC_task_name_for_pid',
        45: 'MSC_task_for_pid',
        46: 'MSC_pid_for_task',
        47: 'MSC_mach_msg2_trap',
        48: 'MSC_macx_swapon',
        49: 'MSC_macx_swapoff',
        50: 'MSC_thread_get_special_reply_port',
        51: 'MSC_macx_triggers',
        52: 'MSC_macx_backing_store_suspend',
        53: 'MSC_macx_backing_store_recovery',
        58: 'MSC_pfz_exit',
        59: 'MSC_swtch_pri',
        60: 'MSC_swtch',
        61: 'MSC_syscall_thread_switch',
        62: 'MSC_clock_sleep_trap',
        70: 'MSC_host_create_mach_voucher_trap',
        72: 'MSC_mach_voucher_extract_attr_recipe_trap',
        76: 'MSC__kernelrpc_mach_port_type_trap',
        77: 'MSC__kernelrpc_mach_port_request_notification_trap',
        89: 'MSC_mach_timebase_info_trap',
        90: 'MSC_mach_wait_until',
        91: 'MSC_mk_timer_create',
        92: 'MSC_mk_timer_destroy',
        93: 'MSC_mk_timer_arm',
        94: 'MSC_mk_timer_cancel',
        95: 'MSC_mk_timer_arm_leeway',
        96: 'MSC_debug_control_port_for_pid',
        100: 'MSC_iokit_user_client_trap'
    }

    f.seek(offset * 8 + base_addr)
    might_be_type = struct.unpack("<H", f.read(2))[0]
    bitmap_length = struct.unpack("<H", f.read(2))[0]
    bitmap = f.read(bitmap_length)

    enabled_syscalls = []
    for byte_index, byte in enumerate(bitmap):
        for bit_position in range(0, 8, 2):
            mask = (byte >> bit_position) & 0b11
            if mask:
                syscall_number = (byte_index * 8) + mask
                syscall_name = arg_types.get(syscall_number, f"machtrap_number_{syscall_number}")
                enabled_syscalls.append(syscall_name)

    return " | ".join(enabled_syscalls)

def get_filter_arg_machtrap_number(f, arg):
    """Convert integer to machtrap number type string."""
    arg_types = {
            10: 'MSC__kernelrpc_mach_vm_allocate_trap',
            11: 'MSC__kernelrpc_mach_vm_purgable_control_trap',
            12: 'MSC__kernelrpc_mach_vm_deallocate_trap',
            13: 'MSC_task_dyld_process_info_notify_get',
            14: 'MSC__kernelrpc_mach_vm_protect_trap',
            15: 'MSC__kernelrpc_mach_vm_map_trap',
            16: 'MSC__kernelrpc_mach_port_allocate_trap',
            18: 'MSC__kernelrpc_mach_port_deallocate_trap',
            19: 'MSC__kernelrpc_mach_port_mod_refs_trap',
            20: 'MSC__kernelrpc_mach_port_move_member_trap',
            21: 'MSC__kernelrpc_mach_port_insert_right_trap',
            22: 'MSC__kernelrpc_mach_port_insert_member_trap',
            23: 'MSC__kernelrpc_mach_port_extract_member_trap',
            24: 'MSC__kernelrpc_mach_port_construct_trap',
            25: 'MSC__kernelrpc_mach_port_destruct_trap',
            26: 'MSC_mach_reply_port',
            27: 'MSC_thread_self_trap',
            28: 'MSC_task_self_trap',
            29: 'MSC_host_self_trap',
            31: 'MSC_mach_msg_trap',
            32: 'MSC_mach_msg_overwrite_trap',
            33: 'MSC_semaphore_signal_trap',
            34: 'MSC_semaphore_signal_all_trap',
            35: 'MSC_semaphore_signal_thread_trap',
            36: 'MSC_semaphore_wait_trap',
            37: 'MSC_semaphore_wait_signal_trap',
            38: 'MSC_semaphore_timedwait_trap',
            39: 'MSC_semaphore_timedwait_signal_trap',
            40: 'MSC__kernelrpc_mach_port_get_attributes_trap',
            41: 'MSC__kernelrpc_mach_port_guard_trap',
            42: 'MSC__kernelrpc_mach_port_unguard_trap',
            43: 'MSC_mach_generate_activity_id',
            44: 'MSC_task_name_for_pid',
            45: 'MSC_task_for_pid',
            46: 'MSC_pid_for_task',
            47: 'MSC_mach_msg2_trap',
            48: 'MSC_macx_swapon',
            49: 'MSC_macx_swapoff',
            50: 'MSC_thread_get_special_reply_port',
            51: 'MSC_macx_triggers',
            52: 'MSC_macx_backing_store_suspend',
            53: 'MSC_macx_backing_store_recovery',
            58: 'MSC_pfz_exit',
            59: 'MSC_swtch_pri',
            60: 'MSC_swtch',
            61: 'MSC_syscall_thread_switch',
            62: 'MSC_clock_sleep_trap',
            70: 'MSC_host_create_mach_voucher_trap',
            72: 'MSC_mach_voucher_extract_attr_recipe_trap',
            76: 'MSC__kernelrpc_mach_port_type_trap',
            77: 'MSC__kernelrpc_mach_port_request_notification_trap',
            89: 'MSC_mach_timebase_info_trap',
            90: 'MSC_mach_wait_until',
            91: 'MSC_mk_timer_create',
            92: 'MSC_mk_timer_destroy',
            93: 'MSC_mk_timer_arm',
            94: 'MSC_mk_timer_cancel',
            95: 'MSC_mk_timer_arm_leeway',
            96: 'MSC_debug_control_port_for_pid',
            100: 'MSC_iokit_user_client_trap'
            }
    if arg in arg_types.keys():
        return '%s' % (arg_types[arg])
    else:
        return '%d' % arg

def get_filter_arg_kernel_mig_routine(f, arg):
    """Convert integer to file (vnode) type string."""
    arg_types = {
            200: 'host_info',
            201: 'host_kernel_version',
            202: 'host_page_size',
            203: 'mach_memory_object_memory_entry',
            204: 'host_processor_info',
            205: 'host_get_io_master',
            206: 'host_get_clock_service',
            207: 'kmod_get_info',
            209: 'host_virtual_physical_table_info',
            213: 'processor_set_default',
            215: 'mach_memory_object_memory_entry_64',
            216: 'host_statistics_from_user',
            217: 'host_request_notification',
            218: 'host_lockgroup_info',
            219: 'host_statistics64_from_user',
            220: 'mach_zone_info',
            221: 'mach_zone_force_gc',
            222: 'host_create_mach_voucher',
            225: 'host_set_atm_diagnostic_flag',
            227: 'mach_memory_info',
            228: 'host_set_multiuser_config_flags',
            231: 'mach_zone_info_for_zone',
            232: 'mach_zone_info_for_largest_zone',
            233: 'mach_zone_get_zlog_zones',
            234: 'mach_zone_get_btlog_records',
            400: 'host_get_boot_info',
            401: 'host_reboot',
            402: 'host_priv_statistics',
            403: 'host_default_memory_manager',
            404: 'vm_wire',
            405: 'thread_wire',
            406: 'vm_allocate_cpm',
            407: 'host_processors',
            412: 'host_get_special_port',
            413: 'host_set_special_port',
            414: 'host_set_exception_ports',
            415: 'host_get_exception_ports',
            416: 'host_swap_exception_ports',
            418: 'mach_vm_wire_external',
            419: 'host_processor_sets',
            420: 'host_processor_set_priv',
            423: 'host_set_UNDServer',
            424: 'host_get_UNDServer',
            425: 'kext_request',
            600: 'host_security_create_task_token',
            601: 'host_security_set_task_token',
            1000: 'clock_get_time',
            1001: 'clock_get_attributes',
            1002: 'clock_alarm',
            1200: 'clock_set_time',
            1201: 'clock_set_attributes',
            2401: 'exception_raise',
            2402: 'exception_raise_state',
            2403: 'exception_raise_state_identity',
            2405: 'mach_exception_raise',
            2406: 'mach_exception_raise_state',
            2407: 'mach_exception_raise_state_identity',
            2800: 'io_object_get_class',
            2801: 'io_object_conforms_to',
            2802: 'io_iterator_next',
            2803: 'io_iterator_reset',
            2804: 'io_service_get_matching_services',
            2805: 'io_registry_entry_get_property',
            2806: 'io_registry_create_iterator',
            2807: 'io_registry_iterator_enter_entry',
            2808: 'io_registry_iterator_exit_entry',
            2809: 'io_registry_entry_from_path',
            2810: 'io_registry_entry_get_name',
            2811: 'io_registry_entry_get_properties',
            2812: 'io_registry_entry_get_property_bytes',
            2813: 'io_registry_entry_get_child_iterator',
            2814: 'io_registry_entry_get_parent_iterator',
            2816: 'io_service_close',
            2817: 'io_connect_get_service',
            2818: 'io_connect_set_notification_port',
            2819: 'io_connect_map_memory',
            2820: 'io_connect_add_client',
            2821: 'io_connect_set_properties',
            2822: 'io_connect_method_scalarI_scalarO',
            2823: 'io_connect_method_scalarI_structureO',
            2824: 'io_connect_method_scalarI_structureI',
            2825: 'io_connect_method_structureI_structureO',
            2826: 'io_registry_entry_get_path',
            2827: 'io_registry_get_root_entry',
            2828: 'io_registry_entry_set_properties',
            2829: 'io_registry_entry_in_plane',
            2830: 'io_object_get_retain_count',
            2831: 'io_service_get_busy_state',
            2832: 'io_service_wait_quiet',
            2833: 'io_registry_entry_create_iterator',
            2834: 'io_iterator_is_valid',
            2836: 'io_catalog_send_data',
            2837: 'io_catalog_terminate',
            2838: 'io_catalog_get_data',
            2839: 'io_catalog_get_gen_count',
            2840: 'io_catalog_module_loaded',
            2841: 'io_catalog_reset',
            2842: 'io_service_request_probe',
            2843: 'io_registry_entry_get_name_in_plane',
            2844: 'io_service_match_property_table',
            2845: 'io_async_method_scalarI_scalarO',
            2846: 'io_async_method_scalarI_structureO',
            2847: 'io_async_method_scalarI_structureI',
            2848: 'io_async_method_structureI_structureO',
            2849: 'io_service_add_notification',
            2850: 'io_service_add_interest_notification',
            2851: 'io_service_acknowledge_notification',
            2852: 'io_connect_get_notification_semaphore',
            2853: 'io_connect_unmap_memory',
            2854: 'io_registry_entry_get_location_in_plane',
            2855: 'io_registry_entry_get_property_recursively',
            2856: 'io_service_get_state',
            2857: 'io_service_get_matching_services_ool',
            2858: 'io_service_match_property_table_ool',
            2859: 'io_service_add_notification_ool',
            2860: 'io_object_get_superclass',
            2861: 'io_object_get_bundle_identifier',
            2862: 'io_service_open_extended',
            2863: 'io_connect_map_memory_into_task',
            2864: 'io_connect_unmap_memory_from_task',
            2865: 'io_connect_method',
            2866: 'io_connect_async_method',
            2867: 'io_connect_set_notification_port_64',
            2868: 'io_service_add_notification_64',
            2869: 'io_service_add_interest_notification_64',
            2870: 'io_service_add_notification_ool_64',
            2871: 'io_registry_entry_get_registry_entry_id',
            2872: 'io_connect_method_var_output',
            2873: 'io_service_get_matching_service',
            2874: 'io_service_get_matching_service_ool',
            2875: 'io_service_get_authorization_id',
            2876: 'io_service_set_authorization_id',
            2877: 'io_server_version',
            2878: 'io_registry_entry_get_properties_bin',
            2879: 'io_registry_entry_get_property_bin',
            2880: 'io_service_get_matching_service_bin',
            2881: 'io_service_get_matching_services_bin',
            2882: 'io_service_match_property_table_bin',
            2883: 'io_service_add_notification_bin',
            2884: 'io_service_add_notification_bin_64',
            2885: 'io_registry_entry_get_path_ool',
            2886: 'io_registry_entry_from_path_ool',
            2887: 'io_device_tree_entry_exists_with_name',
            2888: 'io_registry_entry_get_properties_bin_buf',
            2889: 'io_registry_entry_get_property_bin_buf',
            2890: 'io_service_wait_quiet_with_options',
            3000: 'processor_start_from_user',
            3001: 'processor_exit_from_user',
            3002: 'processor_info',
            3003: 'processor_control',
            3004: 'processor_assign',
            3005: 'processor_get_assignment',
            3200: 'mach_port_names',
            3201: 'mach_port_type',
            3203: 'mach_port_allocate_name',
            3204: 'mach_port_allocate',
            3205: 'mach_port_destroy',
            3206: 'mach_port_deallocate',
            3207: 'mach_port_get_refs',
            3208: 'mach_port_mod_refs',
            3209: 'mach_port_peek',
            3210: 'mach_port_set_mscount',
            3211: 'mach_port_get_set_status_from_user',
            3212: 'mach_port_move_member',
            3213: 'mach_port_request_notification',
            3214: 'mach_port_insert_right',
            3215: 'mach_port_extract_right',
            3216: 'mach_port_set_seqno',
            3217: 'mach_port_get_attributes_from_user',
            3218: 'mach_port_set_attributes',
            3219: 'mach_port_allocate_qos',
            3220: 'mach_port_allocate_full',
            3221: 'task_set_port_space',
            3222: 'mach_port_get_srights',
            3223: 'mach_port_space_info_from_user',
            3224: 'mach_port_dnrequest_info',
            3226: 'mach_port_insert_member',
            3227: 'mach_port_extract_member',
            3228: 'mach_port_get_context_from_user',
            3229: 'mach_port_set_context',
            3230: 'mach_port_kobject_from_user',
            3231: 'mach_port_construct',
            3232: 'mach_port_destruct',
            3233: 'mach_port_guard',
            3234: 'mach_port_unguard',
            3235: 'mach_port_space_basic_info',
            3236: 'mach_port_special_reply_port_reset_link',
            3237: 'mach_port_guard_with_flags',
            3238: 'mach_port_swap_guard',
            3239: 'mach_port_kobject_description_from_user',
            3240: 'mach_port_is_connection_for_service',
            3241: 'mach_port_get_service_port_info',
            3242: 'mach_port_assert_attributes',
            3401: 'task_terminate',
            3402: 'task_threads_from_user',
            3403: 'mach_ports_register',
            3404: 'mach_ports_lookup',
            3405: 'task_info_from_user',
            3406: 'task_set_info',
            3407: 'task_suspend',
            3408: 'task_resume',
            3409: 'task_get_special_port_from_user',
            3410: 'task_set_special_port',
            3411: 'thread_create_from_user',
            3412: 'thread_create_running_from_user',
            3413: 'task_set_exception_ports',
            3414: 'task_get_exception_ports_from_user',
            3415: 'task_swap_exception_ports',
            3418: 'semaphore_create',
            3419: 'semaphore_destroy',
            3420: 'task_policy_set',
            3421: 'task_policy_get',
            3433: 'task_get_state',
            3434: 'task_set_state',
            3435: 'task_set_phys_footprint_limit',
            3436: 'task_suspend2',
            3437: 'task_resume2',
            3438: 'task_purgable_info',
            3439: 'task_get_mach_voucher',
            3440: 'task_set_mach_voucher',
            3441: 'task_swap_mach_voucher',
            3442: 'task_generate_corpse',
            3443: 'task_map_corpse_info',
            3444: 'task_register_dyld_image_infos',
            3445: 'task_unregister_dyld_image_infos',
            3446: 'task_get_dyld_image_infos',
            3447: 'task_register_dyld_shared_cache_image_info',
            3448: 'task_register_dyld_set_dyld_state',
            3449: 'task_register_dyld_get_process_state',
            3450: 'task_map_corpse_info_64',
            3451: 'task_inspect',
            3452: 'task_get_exc_guard_behavior',
            3453: 'task_set_exc_guard_behavior',
            3455: 'mach_task_is_self',
            3456: 'task_dyld_process_info_notify_register',
            3457: 'task_create_identity_token',
            3458: 'task_identity_token_get_task_port',
            3459: 'task_dyld_process_info_notify_deregister',
            3460: 'task_get_exception_ports_info',
            3461: 'task_test_sync_upcall',
            3462: 'task_set_corpse_forking_behavior',
            3463: 'task_test_async_upcall_propagation',
            3464: 'task_map_kcdata_object_64',
            3600: 'thread_terminate',
            3601: 'act_get_state_to_user',
            3602: 'act_set_state_from_user',
            3603: 'thread_get_state_to_user',
            3604: 'thread_set_state_from_user',
            3605: 'thread_suspend',
            3606: 'thread_resume',
            3607: 'thread_abort',
            3608: 'thread_abort_safely',
            3609: 'thread_depress_abort_from_user',
            3610: 'thread_get_special_port_from_user',
            3611: 'thread_set_special_port',
            3612: 'thread_info',
            3613: 'thread_set_exception_ports',
            3614: 'thread_get_exception_ports_from_user',
            3615: 'thread_swap_exception_ports',
            3616: 'thread_policy',
            3617: 'thread_policy_set',
            3618: 'thread_policy_get',
            3624: 'thread_set_policy',
            3625: 'thread_get_mach_voucher',
            3626: 'thread_set_mach_voucher',
            3627: 'thread_swap_mach_voucher',
            3628: 'thread_convert_thread_state',
            3630: 'thread_get_exception_ports_info',
            3800: 'vm_region',
            3801: 'vm_allocate_external',
            3802: 'vm_deallocate',
            3803: 'vm_protect',
            3804: 'vm_inherit',
            3805: 'vm_read',
            3806: 'vm_read_list',
            3807: 'vm_write',
            3808: 'vm_copy',
            3809: 'vm_read_overwrite',
            3810: 'vm_msync',
            3811: 'vm_behavior_set',
            3812: 'vm_map_external',
            3813: 'vm_machine_attribute',
            3814: 'vm_remap_external',
            3815: 'task_wire',
            3816: 'mach_make_memory_entry',
            3817: 'vm_map_page_query',
            3818: 'mach_vm_region_info',
            3819: 'vm_mapped_pages_info',
            3821: 'vm_region_recurse',
            3822: 'vm_region_recurse_64',
            3823: 'mach_vm_region_info_64',
            3824: 'vm_region_64',
            3825: 'mach_make_memory_entry_64',
            3826: 'vm_map_64_external',
            3830: 'vm_purgable_control',
            3831: 'vm_map_exec_lockdown',
            3832: 'vm_remap_new_external',
            4000: 'processor_set_statistics',
            4005: 'processor_set_tasks',
            4006: 'processor_set_threads',
            4008: 'processor_set_stack_usage',
            4009: 'processor_set_info',
            4010: 'processor_set_tasks_with_flavor',
            4800: 'mach_vm_allocate_external',
            4801: 'mach_vm_deallocate',
            4802: 'mach_vm_protect',
            4803: 'mach_vm_inherit',
            4804: 'mach_vm_read',
            4805: 'mach_vm_read_list',
            4806: 'mach_vm_write',
            4807: 'mach_vm_copy',
            4808: 'mach_vm_read_overwrite',
            4809: 'mach_vm_msync',
            4810: 'mach_vm_behavior_set',
            4811: 'mach_vm_map_external',
            4812: 'mach_vm_machine_attribute',
            4813: 'mach_vm_remap_external',
            4814: 'mach_vm_page_query',
            4815: 'mach_vm_region_recurse',
            4816: 'mach_vm_region',
            4817: '_mach_make_memory_entry',
            4818: 'mach_vm_purgable_control',
            4819: 'mach_vm_page_info',
            4820: 'mach_vm_page_range_query',
            4821: 'mach_vm_remap_new_external',
            4900: 'mach_memory_entry_purgable_control',
            4901: 'mach_memory_entry_access_tracking',
            4902: 'mach_memory_entry_ownership',
            5400: 'mach_voucher_extract_attr_content',
            5401: 'mach_voucher_extract_attr_recipe',
            5402: 'mach_voucher_extract_all_attr_recipes',
            5403: 'mach_voucher_attr_command',
            5404: 'mach_voucher_debug_info',
            6200: 'UNDAlertCompletedWithResult_rpc',
            6201: 'UNDNotificationCreated_rpc',
            8000: 'task_restartable_ranges_register',
            8001: 'task_restartable_ranges_synchronize'
            }
    if arg in arg_types.keys():
        return '%s' % (arg_types[arg])
    else:
        return '%d' % arg

def get_filter_arg_fnctl_bitmask(f, offset):
    """Convert integer to fnctl bitmask string."""
    bitmask_types = {
            0x0001: 'F_RDLCK',
            0x0002: 'F_UNLCK',
            0x0003: 'F_WRLCK',
            0x0010: 'F_SETLK',
            0x0011: 'F_SETLKW',
            0x0012: 'F_GETLK',
            0x0040: 'F_GETLK64',
            0x0041: 'F_SETLK64',
            0x0042: 'F_SETLKW64',
            0x0080: 'F_OFD_GETLK',
            0x0081: 'F_OFD_SETLK',
            0x0082: 'F_OFD_SETLKW',
            0x0100: 'F_CANCELLK',
            0x0200: 'F_PREPEND',
            0x0400: 'F_APPEND',
            0x0800: 'F_WAIT',
            0x1000: 'F_FLOCK',
            0x2000: 'F_SHARE',
            0x4000: 'F_EXCL',
            0x8000: 'F_NBMAND'
            }

    f.seek(offset * 8 + base_addr)
    might_be_type = struct.unpack("<H", f.read(2))[0]
    bitmap_length = struct.unpack("<H", f.read(2))[0]
    bitmap = f.read(bitmap_length)

    enabled_syscalls = []
    for byte_index, byte in enumerate(bitmap):
        for bit_position in range(0, 8, 2):
            mask = (byte >> bit_position) & 0b11
            if mask:
                syscall_number = (byte_index * 8) + mask
                syscall_name = bitmask_types.get(syscall_number, f"fnctl_number_{syscall_number}")
                enabled_syscalls.append(syscall_name)

    return " | ".join(enabled_syscalls)

def get_filter_arg_fcntl(f, arg):
    """Convert integer to fcntl type string."""
    arg_types = {
            0: 'F_DUPFD',
            1: 'F_GETFD',
            2: 'F_SETFD',
            3: 'F_GETFL',
            4: 'F_SETFL',
            5: 'F_GETOWN',
            6: 'F_SETOWN',
            7: 'F_GETLK',
            8: 'F_SETLK',
            9: 'F_SETLKW',
            10: 'F_SETLKWTIMEOUT',
            40: 'F_FLUSH_DATA',
            41: 'F_CHKCLEAN',
            42: 'F_PREALLOCATE',
            43: 'F_SETSIZE',
            44: 'F_RDADVISE',
            45: 'F_RDAHEAD',
            48: 'F_NOCACHE',
            49: 'F_LOG2PHYS',
            50: 'F_GETPATH',
            51: 'F_FULLFSYNC',
            52: 'F_PATHPKG_CHECK',
            53: 'F_FREEZE_FS',
            54: 'F_THAW_FS',
            55: 'F_GLOBAL_NOCACHE',
            56: 'F_OPENFROM',
            57: 'F_UNLINKFROM',
            58: 'F_CHECK_OPENEVT',
            59: 'F_ADDSIGS',
            60: 'F_MARKDEPENDENCY',
            61: 'F_ADDFILESIGS',
            62: 'F_NODIRECT',
            63: 'F_GETPROTECTIONCLASS',
            64: 'F_SETPROTECTIONCLASS',
            65: 'F_LOG2PHYS_EXT',
            66: 'F_GETLKPID',
            67: 'F_DUPFD_CLOEXEC',
            68: 'F_SETSTATICCONTENT',
            69: 'F_MOVEDATAEXTENTS',
            70: 'F_SETBACKINGSTORE',
            71: 'F_GETPATH_MTMINFO',
            72: 'F_GETCODEDIR',
            73: 'F_SETNOSIGPIPE',
            74: 'F_GETNOSIGPIPE',
            75: 'F_TRANSCODEKEY',
            76: 'F_SINGLE_WRITER',
            77: 'F_GETPROTECTIONLEVEL',
            78: 'F_FINDSIGS',
            79: 'F_GETDEFAULTPROTLEVEL',
            80: 'F_MAKECOMPRESSED',
            81: 'F_SET_GREEDY_MODE',
            82: 'F_SETIOTYPE',
            83: 'F_ADDFILESIGS_FOR_DYLD_SIM',
            84: 'F_RECYCLE',
            85: 'F_BARRIERFSYNC',
            90: 'F_OFD_SETLK',
            91: 'F_OFD_SETLKW',
            92: 'F_OFD_GETLK',
            93: 'F_OFD_SETLKWTIMEOUT',
            94: 'F_OFD_GETLKPID',
            95: 'F_SETCONFINED',
            96: 'F_GETCONFINED',
            97: 'F_ADDFILESIGS_RETURN',
            98: 'F_CHECK_LV',
            99: 'F_PUNCHHOLE',
            100: 'F_TRIM_ACTIVE_FILE',
            101: 'F_SPECULATIVE_READ',
            102: 'F_GETPATH_NOFIRMLINK',
            103: 'F_ADDFILESIGS_INFO',
            104: 'F_ADDFILESUPPL',
            105: 'F_GETSIGSINFO',
            106: 'F_SETLEASE',
            107: 'F_GETLEASE',
            108: 'F_ASSERT_BG_ACCESS',
            109: 'F_RELEASE_BG_ACCESS',
            110: 'F_TRANSFEREXTENTS'
            }
    if arg in arg_types.keys():
        return '%s' % (arg_types[arg])
    else:
        return '%d' % arg

def get_filter_arg_socket_option_level(f, arg):
    """Convert integer to file (vnode) type string."""
    arg_types = {
            0: 'IPPROTO_HOPOPTS',
            1: 'IPPROTO_ICMP',
            2: 'IPPROTO_IGMP',
            3: 'IPPROTO_GGP',
            4: 'IPPROTO_IPV4',
            6: 'IPPROTO_TCP',
            7: 'IPPROTO_ST',
            8: 'IPPROTO_EGP',
            9: 'IPPROTO_PIGP',
            10: 'IPPROTO_RCCMON',
            11: 'IPPROTO_NVPII',
            12: 'IPPROTO_PUP',
            13: 'IPPROTO_ARGUS',
            14: 'IPPROTO_EMCON',
            15: 'IPPROTO_XNET',
            16: 'IPPROTO_CHAOS',
            17: 'IPPROTO_UDP',
            18: 'IPPROTO_MUX',
            19: 'IPPROTO_MEAS',
            20: 'IPPROTO_HMP',
            21: 'IPPROTO_PRM',
            22: 'IPPROTO_IDP',
            23: 'IPPROTO_TRUNK1',
            24: 'IPPROTO_TRUNK2',
            25: 'IPPROTO_LEAF1',
            26: 'IPPROTO_LEAF2',
            27: 'IPPROTO_RDP',
            28: 'IPPROTO_IRTP',
            29: 'IPPROTO_TP',
            30: 'IPPROTO_BLT',
            31: 'IPPROTO_NSP',
            32: 'IPPROTO_INP',
            33: 'IPPROTO_SEP',
            34: 'IPPROTO_3PC',
            35: 'IPPROTO_IDPR',
            36: 'IPPROTO_XTP',
            37: 'IPPROTO_DDP',
            38: 'IPPROTO_CMTP',
            39: 'IPPROTO_TPXX',
            40: 'IPPROTO_IL',
            41: 'IPPROTO_IPV6',
            42: 'IPPROTO_SDRP',
            43: 'IPPROTO_ROUTING',
            44: 'IPPROTO_FRAGMENT',
            45: 'IPPROTO_IDRP',
            46: 'IPPROTO_RSVP',
            47: 'IPPROTO_GRE',
            48: 'IPPROTO_MHRP',
            49: 'IPPROTO_BHA',
            50: 'IPPROTO_ESP',
            51: 'IPPROTO_AH',
            52: 'IPPROTO_INLSP',
            53: 'IPPROTO_SWIPE',
            54: 'IPPROTO_NHRP',
            58: 'IPPROTO_ICMPV6',
            59: 'IPPROTO_NONE',
            60: 'IPPROTO_DSTOPTS',
            61: 'IPPROTO_AHIP',
            62: 'IPPROTO_CFTP',
            63: 'IPPROTO_HELLO',
            64: 'IPPROTO_SATEXPAK',
            65: 'IPPROTO_KRYPTOLAN',
            66: 'IPPROTO_RVD',
            67: 'IPPROTO_IPPC',
            68: 'IPPROTO_ADFS',
            69: 'IPPROTO_SATMON',
            70: 'IPPROTO_VISA',
            71: 'IPPROTO_IPCV',
            72: 'IPPROTO_CPNX',
            73: 'IPPROTO_CPHB',
            74: 'IPPROTO_WSN',
            75: 'IPPROTO_PVP',
            76: 'IPPROTO_BRSATMON',
            77: 'IPPROTO_ND',
            78: 'IPPROTO_WBMON',
            79: 'IPPROTO_WBEXPAK',
            80: 'IPPROTO_EON',
            81: 'IPPROTO_VMTP',
            82: 'IPPROTO_SVMTP',
            83: 'IPPROTO_VINES',
            84: 'IPPROTO_TTP',
            85: 'IPPROTO_IGP',
            86: 'IPPROTO_DGP',
            87: 'IPPROTO_TCF',
            88: 'IPPROTO_IGRP',
            89: 'IPPROTO_OSPFIGP',
            90: 'IPPROTO_SRPC',
            91: 'IPPROTO_LARP',
            92: 'IPPROTO_MTP',
            93: 'IPPROTO_AX25',
            94: 'IPPROTO_IPEIP',
            95: 'IPPROTO_MICP',
            96: 'IPPROTO_SCCSP',
            97: 'IPPROTO_ETHERIP',
            98: 'IPPROTO_ENCAP',
            99: 'IPPROTO_APES',
            100: 'IPPROTO_GMTP',
            103: 'IPPROTO_PIM',
            108: 'IPPROTO_IPCOMP',
            113: 'IPPROTO_PGM',
            132: 'IPPROTO_SCTP',
            254: 'IPPROTO_DIVERT',
            255: 'IPPROTO_RAW',
            65535: 'SOL_SOCKET'
            }
    if arg in arg_types.keys():
        return '%s' % (arg_types[arg])
    else:
        return '%d' % arg

def get_filter_arg_socket_option_name(f, arg):
    """Convert integer to option name type string."""
    arg_types = {
            1: 'SO_DEBUG',
            2: 'SO_ACCEPTCONN',
            4: 'SO_REUSEADDR',
            8: 'SO_KEEPALIVE',
            16: 'SO_DONTROUTE',
            32: 'SO_BROADCAST',
            64: 'SO_USELOOPBACK',
            128: 'SO_LINGER',
            256: 'SO_OOBINLINE',
            512: 'SO_REUSEPORT',
            1024: 'SO_TIMESTAMP',
            2048: 'SO_TIMESTAMP_MONOTONIC',
            4096: 'SO_NOWAKEFROMSLEEP',
            4097: 'SO_SNDBUF',
            4098: 'SO_RCVBUF',
            4099: 'SO_SNDLOWAT',
            4100: 'SO_RCVLOWAT',
            4101: 'SO_SNDTIMEO',
            4102: 'SO_RCVTIMEO',
            4103: 'SO_ERROR',
            4104: 'SO_TYPE',
            4112: 'SO_LABEL',
            4113: 'SO_PEERLABEL',
            4128: 'SO_NREAD',
            4129: 'SO_NKE',
            4130: 'SO_NOSIGPIPE',
            4131: 'SO_NOADDRERR',
            4132: 'SO_NWRITE',
            4133: 'SO_REUSESHAREUID',
            4134: 'SO_NOTIFYCONFLICT',
            4135: 'SO_UPCALLCLOSEWAIT',
            4224: 'SO_LINGER',
            4225: 'SO_RESTRICTIONS',
            4226: 'SO_RANDOMPORT',
            4227: 'SO_NP_EXTENSIONS',
            4229: 'SO_EXECPATH',
            4230: 'SO_TRAFFIC_CLASS',
            4231: 'SO_RECV_TRAFFIC_CLASS',
            4232: 'SO_TRAFFIC_CLASS_DBG',
            4233: 'SO_OPTION_UNUSED_0',
            4240: 'SO_PRIVILEGED_TRAFFIC_CLASS',
            4241: 'SO_DEFUNCTIT',
            4352: 'SO_DEFUNCTOK',
            4353: 'SO_ISDEFUNCT',
            4354: 'SO_OPPORTUNISTIC',
            4355: 'SO_FLUSH',
            4356: 'SO_RECV_ANYIF',
            4357: 'SO_TRAFFIC_MGT_BACKGROUND',
            4358: 'SO_FLOW_DIVERT_TOKEN',
            4359: 'SO_DELEGATED',
            4360: 'SO_DELEGATED_UUID',
            4361: 'SO_NECP_ATTRIBUTES',
            4368: 'SO_CFIL_SOCK_ID',
            4369: 'SO_NECP_CLIENTUUID',
            4370: 'SO_NUMRCVPKT',
            4371: 'SO_AWDL_UNRESTRICTED',
            4372: 'SO_EXTENDED_BK_IDLE',
            4373: 'SO_MARK_CELLFALLBACK',
            4374: 'SO_NET_SERVICE_TYPE',
            4375: 'SO_QOSMARKING_POLICY_OVERRIDE',
            4376: 'SO_INTCOPROC_ALLOW',
            4377: 'SO_NETSVC_MARKING_LEVEL',
            4384: 'SO_NECP_LISTENUUID',
            4386: 'SO_MPKL_SEND_INFO',
            4387: 'SO_STATISTICS_EVENT',
            4388: 'SO_WANT_KEV_SOCKET_CLOSED',
            4389: 'SO_MARK_KNOWN_TRACKER',
            4390: 'SO_MARK_KNOWN_TRACKER_NON_APP_INITIATED',
            4391: 'SO_MARK_WAKE_PKT',
            4392: 'SO_RECV_WAKE_PKT',
            4393: 'SO_MARK_APPROVED_APP_DOMAIN',
            4400: 'SO_FALLBACK_MODE',
            4401: 'SO_RESOLVER_SIGNATURE',
            4402: 'SO_MARK_CELLFALLBACK_UUID',
            8192: 'SO_DONTTRUNC',
            16384: 'SO_WANTMORE',
            32768: 'SO_WANTOOBFLAG'
            }
    if arg in arg_types.keys():
        return '%s' % (arg_types[arg])
    else:
        return '%d' % arg

def get_filter_arg_memorystatus_control(f, arg):
    """Convert integer to file (vnode) type string."""
    arg_types = {
            1: 'MEMORYSTATUS_CMD_GET_PRIORITY_LIST',
            2: 'MEMORYSTATUS_CMD_SET_PRIORITY_PROPERTIES',
            3: 'MEMORYSTATUS_CMD_GET_JETSAM_SNAPSHOT',
            4: 'MEMORYSTATUS_CMD_GET_PRESSURE_STATUS',
            5: 'MEMORYSTATUS_CMD_SET_JETSAM_HIGH_WATER_MARK',
            6: 'MEMORYSTATUS_CMD_SET_JETSAM_TASK_LIMIT',
            7: 'MEMORYSTATUS_CMD_SET_MEMLIMIT_PROPERTIES',
            8: 'MEMORYSTATUS_CMD_GET_MEMLIMIT_PROPERTIES',
            9: 'MEMORYSTATUS_CMD_PRIVILEGED_LISTENER_ENABLE',
            10: 'MEMORYSTATUS_CMD_PRIVILEGED_LISTENER_DISABLE',
            11: 'MEMORYSTATUS_CMD_AGGRESSIVE_JETSAM_LENIENT_MODE_ENABLE',
            12: 'MEMORYSTATUS_CMD_AGGRESSIVE_JETSAM_LENIENT_MODE_DISABLE',
            13: 'MEMORYSTATUS_CMD_GET_MEMLIMIT_EXCESS',
            14: 'MEMORYSTATUS_CMD_ELEVATED_INACTIVEJETSAMPRIORITY_ENABLE',
            15: 'MEMORYSTATUS_CMD_ELEVATED_INACTIVEJETSAMPRIORITY_DISABLE',
            16: 'MEMORYSTATUS_CMD_SET_PROCESS_IS_MANAGED',
            17: 'MEMORYSTATUS_CMD_GET_PROCESS_IS_MANAGED',
            18: 'MEMORYSTATUS_CMD_SET_PROCESS_IS_FREEZABLE',
            19: 'MEMORYSTATUS_CMD_GET_PROCESS_IS_FREEZABLE',
            20: 'MEMORYSTATUS_CMD_FREEZER_CONTROL',
            21: 'MEMORYSTATUS_CMD_GET_AGGRESSIVE_JETSAM_LENIENT_MODE',
            22: 'MEMORYSTATUS_CMD_INCREASE_JETSAM_TASK_LIMIT',
            23: 'MEMORYSTATUS_CMD_SET_TESTING_PID',
            24: 'MEMORYSTATUS_CMD_GET_PROCESS_IS_FROZEN',
            25: 'MEMORYSTATUS_CMD_MARK_PROCESS_COALITION_SWAPPABLE',
            26: 'MEMORYSTATUS_CMD_GET_PROCESS_COALITION_IS_SWAPPABLE',
            28: 'MEMORYSTATUS_CMD_CONVERT_MEMLIMIT_MB',
            100: 'MEMORYSTATUS_CMD_GRP_SET_PROPERTIES',
            1000: 'MEMORYSTATUS_CMD_TEST_JETSAM',
            1001: 'MEMORYSTATUS_CMD_TEST_JETSAM_SORT'
            }
    if arg in arg_types.keys():
        return '%s' % (arg_types[arg])
    else:
        return '%d' % arg


def get_filter_arg_mach_exception_type(f, arg):
    """Convert integer to mach exception type string."""
    arg_types = {
        1: 'EXC_BAD_ACCESS',
        2: 'EXC_BAD_INSTRUCTION',
        3: 'EXC_ARITHMETIC',
        4: 'EXC_EMULATION',
        5: 'EXC_SOFTWARE',
        6: 'EXC_BREAKPOINT',
        7: 'EXC_SYSCALL',
        8: 'EXC_MACH_SYSCALL',
        9: 'EXC_RPC_ALERT',
        10: 'EXC_CRASH',
        11: 'EXC_RESOURCE',
        12: 'EXC_GUARD',
        13: 'EXC_CORPSE_NOTIFY',
    }
    if arg in arg_types.keys():
        return '%s' % (arg_types[arg])
    else:
        return '%d' % arg


def get_filter_arg_mach_exception_behavior(f, arg):
    """Convert integer to mach exception behavior type string."""
    arg_types = {
            1: 'EXCEPTION_DEFAULT',
            2: 'EXCEPTION_STATE',
            3: 'EXCEPTION_STATE_IDENTITY',
            4: 'EXCEPTION_IDENTITY_PROTECTED',
            5: 'EXCEPTION_STATE_IDENTITY_PROTECTED',
            }
    if arg in arg_types.keys():
        return '%s' % (arg_types[arg])
    else:
        return '%d' % arg


def get_filter_arg_kas_info_selector(f, arg):
    """Convert integer to kas_info selector type string."""
    arg_types = {
            0: 'KAS_INFO_KERNEL_TEXT_SLIDE_SELECTOR',
            1: 'KAS_INFO_KERNEL_SEGMENT_VMADDR_SELECTOR',
            2: 'KAS_INFO_SPTM_TEXT_SLIDE_SELECTOR',
            3: 'KAS_INFO_TXM_TEXT_SLIDE_SELECTOR',
            }
    if arg in arg_types.keys():
        return '%s' % (arg_types[arg])
    else:
        return '%d' % arg


def get_filter_arg_codesigning_operation(f, arg):
    """Convert integer to codesigning-operation type string."""
    arg_types = {
            0: 'CS_OPS_STATUS',
            1: 'CS_OPS_MARKINVALID',
            2: 'CS_OPS_MARKHARD',
            3: 'CS_OPS_MARKKILL',
            5: 'CS_OPS_CDHASH',
            6: 'CS_OPS_PIDOFFSET',
            7: 'CS_OPS_ENTITLEMENTS_BLOB',
            8: 'CS_OPS_MARKRESTRICT',
            9: 'CS_OPS_SET_STATUS',
            10: 'CS_OPS_BLOB',
            11: 'CS_OPS_IDENTITY',
            12: 'CS_OPS_CLEARINSTALLER',
            13: 'CS_OPS_CLEARPLATFORM',
            14: 'CS_OPS_TEAMID',
            15: 'CS_OPS_CLEAR_LV',
            16: 'CS_OPS_DER_ENTITLEMENTS_BLOB',
            17: 'CS_OPS_VALIDATION_CATEGORY'
            }
    if arg in arg_types.keys():
        return '%s' % (arg_types[arg])
    else:
        return '%d' % arg


def get_filter_arg_task_special_port(f, arg):
    """Convert integer to task_special_port type string."""
    arg_types = {
            1: 'TASK_KERNEL_PORT',
            2: 'TASK_HOST_PORT',
            3: 'TASK_NAME_PORT',
            4: 'TASK_BOOTSTRAP_PORT',
            5: 'TASK_INSPECT_PORT',
            6: 'TASK_READ_PORT',
            9: 'TASK_ACCESS_PORT',
            10: 'TASK_DEBUG_CONTROL_PORT',
            11: 'TASK_RESOURCE_NOTIFY_PORT'
            }
    if arg in arg_types.keys():
        return '%s' % (arg_types[arg])
    else:
        return '%d' % arg

def get_filter_arg_owner(f, arg):
    """Convert integer to process owner string."""
    arg_types = {
            0x01: "self",
            0x02: "pgrp",
            0x03: "others",
            0x04: "children",
            0x05: "same-sandbox"
            }
    if arg in arg_types.keys():
        return '%s' % (arg_types[arg])
    else:
        return '%d' % arg


def get_filter_arg_socket_domain(f, arg):
    """Convert integer to socket domain string."""
    arg_types = {
            0: "AF_UNSPEC",
            1: "AF_UNIX",
            2: "AF_INET",
            3: "AF_IMPLINK",
            4: "AF_PUP",
            5: "AF_CHAOS",
            6: "AF_NS",
            7: "AF_ISO",
            8: "AF_ECMA",
            9: "AF_DATAKIT",
            10: "AF_CCITT",
            11: "AF_SNA",
            12: "AF_DECnet",
            13: "AF_DLI",
            14: "AF_LAT",
            15: "AF_HYLINK",
            16: "AF_APPLETALK",
            17: "AF_ROUTE",
            18: "AF_LINK",
            19: "pseudo_AF_XTP",
            20: "AF_COIP",
            21: "AF_CNT",
            22: "pseudo_AF_RTIP",
            23: "AF_IPX",
            24: "AF_SIP",
            25: "pseudo_AF_PIP",
            27: "AF_NDRV",
            28: "AF_ISDN",
            29: "pseudo_AF_KEY",
            30: "AF_INET6",
            31: "AF_NATM",
            32: "AF_SYSTEM",
            33: "AF_NETBIOS",
            34: "AF_PPP",
            35: "pseudo_AF_HDRCMPLT",
            36: "AF_RESERVED_36",
            37: "AF_IEEE80211",
            38: "AF_UTUN",
            40: "AF_MAX"
            }
    if arg in arg_types.keys():
        return '%s' % (arg_types[arg])
    else:
        return '%d' % arg


def get_filter_arg_socket_type(f, arg):
    """Convert integer to socket type string."""
    arg_types = {
        0x01: "SOCK_STREAM",
        0x02: "SOCK_DGRAM",
        0x03: "SOCK_RAW",
        0x04: "SOCK_RDM",
        0x05: "SOCK_SEQPACKET"
        }
    if arg in arg_types.keys():
        return '"%s"' % (arg_types[arg])
    else:
        return '%d' % arg


def get_none(f, arg):
    """Dumb callback function"""
    return None


def get_filter_arg_privilege_id(f, arg):
    """Convert integer to privilege id string."""
    arg_types = {
            1000: "PRIV_ADJTIME",
            1001: "PRIV_PROC_UUID_POLICY",
            1002: "PRIV_GLOBAL_PROC_INFO",
            1003: "PRIV_SYSTEM_OVERRIDE",
            1004: "PRIV_HW_DEBUG_DATA",
            1005: "PRIV_SELECTIVE_FORCED_IDLE",
            1006: "PRIV_PROC_TRACE_INSPECT",
            1008: "PRIV_KERNEL_WORK_INTERNAL",
            6000: "PRIV_VM_PRESSURE",
            6001: "PRIV_VM_JETSAM",
            6002: "PRIV_VM_FOOTPRINT_LIMIT",
            10000: "PRIV_NET_PRIVILEGED_TRAFFIC_CLASS",
            10001: "PRIV_NET_PRIVILEGED_SOCKET_DELEGATE",
            10002: "PRIV_NET_INTERFACE_CONTROL",
            10003: "PRIV_NET_PRIVILEGED_NETWORK_STATISTICS",
            10004: "PRIV_NET_PRIVILEGED_NECP_POLICIES",
            10005: "PRIV_NET_RESTRICTED_AWDL",
            10006: "PRIV_NET_PRIVILEGED_NECP_MATCH",
            11000: "PRIV_NETINET_RESERVEDPORT",
            14000: "PRIV_VFS_OPEN_BY_ID",
        }
    if arg in arg_types.keys():
        return '"%s"' % (arg_types[arg])
    else:
        return '%d' % arg


def get_filter_arg_process_attribute(f, arg):
    """Convert integer to process attribute string."""
    arg_types = {
            0: 'unknown',
            1: 'is-installer',
            2: 'is-restricted',
            3: 'is-initproc',
            4: 'is-platform-binary',
            5: 'is-sandboxed',
            6: 'is-nvram-privileged',
            7: 'is-sandcastle-constrained',
            8: 'is-datavault-controller',
            9: 'is-apple-signed-executable',
            10: 'is-catalyst-binary',
            11: 'is-translated-binary',
            12: 'is-protoboxed',
            13: 'is-rsr-binary'
        }
    if arg in arg_types.keys():
        return '%s' % (arg_types[arg])
    else:
        return '%d' % arg


def get_filter_arg_csr(f, arg):
    """Convert integer to csr string."""
    arg_types = {
            1: 'CSR_ALLOW_UNTRUSTED_KEXTS',
            2: 'CSR_ALLOW_UNRESTRICTED_FS',
            4: 'CSR_ALLOW_TASK_FOR_PID',
            8: 'CSR_ALLOW_KERNEL_DEBUGGER',
            16: 'CSR_ALLOW_APPLE_INTERNAL',
            32: 'CSR_ALLOW_UNRESTRICTED_DTRACE',
            64: 'CSR_ALLOW_UNRESTRICTED_NVRAM',
            128: 'CSR_ALLOW_DEVICE_CONFIGURATION',
        }
    if arg in arg_types.keys():
        return '"%s"' % (arg_types[arg])
    else:
        return '%d' % arg


def get_filter_arg_host_port(f, arg):
    """Convert integer to host special port string."""
    arg_types = {
            8: 'HOST_DYNAMIC_PAGER_PORT',
            9: 'HOST_AUDIT_CONTROL_PORT',
            10: 'HOST_USER_NOTIFICATION_PORT',
            11: 'HOST_AUTOMOUNTD_PORT',
            12: 'HOST_LOCKD_PORT',
            13: 'unknown: 13',
            14: 'HOST_SEATBELT_PORT',
            15: 'HOST_KEXTD_PORT',
            16: 'HOST_CHUD_PORT',
            17: 'HOST_UNFREED_PORT',
            18: 'HOST_AMFID_PORT',
            19: 'HOST_GSSD_PORT',
            20: 'HOST_TELEMETRY_PORT',
            21: 'HOST_ATM_NOTIFICATION_PORT',
            22: 'HOST_COALITION_PORT',
            23: 'HOST_SYSDIAGNOSE_PORT',
            24: 'HOST_XPC_EXCEPTION_PORT',
            25: 'HOST_CONTAINERD_PORT',
        }
    if arg in arg_types.keys():
        return '"%s"' % (arg_types[arg])
    else:
        return '%d' % arg


def get_filter_arg_necp_client_action(f, arg):
    return "[UNSUPPORTED]"


"""An array (dictionary) of filter converting items

A filter is identied by a filter id and a filter argument. They are
both stored in binary format (numbers) inside the binary sandbox
profile file.

Each item in the dictionary is identied by the filter id (used in
hexadecimal). The value of each item is the string form of the filter id
and the callback function used to convert the binary form the filter
argument to a string form.

While there is a one-to-one mapping between the binary form and the
string form of the filter id, that is not the case for the filter
argument. To convert the binary form of the filter argument to its
string form we use one of the callback functions above; almost all
callback function names start with get_filter_arg_.
"""

def convert_filter_callback(f, sandbox_data, keep_builtin_filters_arg, filter_id, filter_arg):
    """Convert filter from binary form to string.

    Binary form consists of filter id and filter argument:
      * filter id is the index inside the filters array above
      * filter argument is an actual parameter (such as a port number),
        a file offset or a regular expression index

    The string form consists of the name of the filter (as extracted
    from the filters array above) and a string representation of the
    filter argument. The string form of the filter argument if obtained
    from the binary form through the use of the callback function (as
    extracted frm the filters array above).

    Function arguments are:
      f: the binary sandbox profile file
      regex_list: list of regular expressions
      filter_id: the binary form of the filter id
      filter_arg: the binary form of the filter argument
    """

    global regex_list
    global keep_builtin_filters
    global global_vars
    global base_addr
    keep_builtin_filters = keep_builtin_filters_arg
    
    global_vars = sandbox_data.global_vars
    regex_list = sandbox_data.regex_list
    base_addr = sandbox_data.base_addr

    if not Filters.exists(filter_id):
        logger.warn("filter_id {} not in keys".format(filter_id))
        return (None, None)
    filter = Filters.get(filter_id)
    
    if not filter["arg_process_fn"]:
        logger.warn("no function for filter {}".format(filter_id))
        return (None, None)
    if filter["arg_process_fn"] == "get_filter_arg_string_by_offset_with_type":
        (append, result) = globals()[filter["arg_process_fn"]](f, filter_arg)
        if filter_id == 0x01 and append == "path":
            append = "subpath"
        if result == None and filter["name"] != "debug-mode":
            logger.warn("result of calling string offset for filter {} is none".format(filter_id))
            return (None, None)
        return (filter["name"] + ("-" if len(filter["name"]) else "") + append, result)

    result = globals()[filter["arg_process_fn"]](f, filter_arg)
    if result == None and filter["name"] != "debug-mode":
        logger.warn("result of calling arg_process_fn for filter {} is none".format(filter_id))
        return (None, None)
    return (filter["name"], result)


def convert_modifier_callback(f, sandbox_data, modifier_id, modifier_argument):
    """Convert filter from binary form to string.

    Binary form consists of filter id and filter argument:
      * filter id is the index inside the filters array above
      * filter argument is an actual parameter (such as a port number),
        a file offset or a regular expression index

    The string form consists of the name of the filter (as extracted
    from the filters array above) and a string representation of the
    filter argument. The string form of the filter argument if obtained
    from the binary form through the use of the callback function (as
    extracted frm the filters array above).

    Function arguments are:
      f: the binary sandbox profile file
      regex_list: list of regular expressions
      filter_id: the binary form of the filter id
      filter_arg: the binary form of the filter argument
    """

    global regex_list
    global keep_builtin_filters
    global global_vars
    global base_addr

    global_vars = sandbox_data.global_vars
    regex_list = sandbox_data.regex_list
    base_addr = sandbox_data.base_addr

    if not Modifiers.exists(modifier_id):
        return "== NEED TO ADD MODIFIERS SUPPORT"
    modifier_func = Modifiers.get(modifier_id)

    if modifier_func["arg_process_fn"] == "get_filter_arg_string_by_offset_with_type":
        (append, result) = globals()[modifier_func["arg_process_fn"]](f, modifier_argument)
        result += append
        return result
    result = globals()[modifier_func["arg_process_fn"]](f, modifier_argument)
    return result
