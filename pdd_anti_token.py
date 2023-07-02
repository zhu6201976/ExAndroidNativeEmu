"""
com.xunmeng.pinduoduo
"""
import logging
import posixpath
import sys

from unicorn import *
from unicorn.arm_const import *

import androidemu.utils.debug_utils
from androidemu.emulator import Emulator
from androidemu.java.java_class_def import JavaClassDef
from androidemu.java.java_field_def import JavaFieldDef
from androidemu.java.java_method_def import java_method_def
from androidemu.java.classes.string import String
from androidemu.utils.chain_log import ChainLogger

g_cfd = ChainLogger(sys.stdout, "./ins-tmp.txt")


# Add debugging.
def hook_code(mu, address, size, user_data):
    try:
        emu = user_data
        if (not emu.memory.check_addr(address, UC_PROT_EXEC)):
            logger.error("addr 0x%08X out of range" % (address,))
            sys.exit(-1)

        # androidemu.utils.debug_utils.dump_registers(mu, sys.stdout)
        androidemu.utils.debug_utils.dump_code(emu, address, size, g_cfd)
    except Exception as e:
        logger.exception("exception in hook_code")
        sys.exit(-1)


def hook_mem_read(uc, access, address, size, value, user_data):
    pc = uc.reg_read(UC_ARM_REG_PC)

    if (address == 0xCBC80640):
        logger.debug("read mutex")
        data = uc.mem_read(address, size)
        v = int.from_bytes(data, byteorder='little', signed=False)
        logger.debug(
            ">>> Memory READ at 0x%08X, data size = %u,  data value = 0x%08X, pc: 0x%08X," % (address, size, v, pc))


def hook_mem_write(uc, access, address, size, value, user_data):
    pc = uc.reg_read(UC_ARM_REG_PC)
    if (address == 0xCBC80640):
        logger.debug("write mutex")
        logger.debug(
            ">>> Memory WRITE at 0x%08X, data size = %u, data value = 0x%08X, pc: 0x%08X" % (address, size, value, pc))


class DeviceNative(metaclass=JavaClassDef, jvm_name='com/xunmeng/pinduoduo/secure/DeviceNative'):

    def __init__(self):
        pass

    @java_method_def(name='info', signature='(Landroid/content/Context;J)Ljava/lang/String;', native=True)
    def info(self, mu):
        pass

    @java_method_def(name='info2', signature='(Landroid/content/Context;J)Ljava/lang/String;', native=True)
    def info2(self, mu):
        pass


class PLog(metaclass=JavaClassDef, jvm_name='com/tencent/mars/xlog/PLog'):

    def __init__(self):
        pass

    @staticmethod
    @java_method_def(name='i', signature='(Ljava/lang/String;Ljava/lang/String;)V', native=False)
    def i(mu):
        pass


class Build(metaclass=JavaClassDef, jvm_name='android/os/Build',
            jvm_fields=[
                JavaFieldDef('SERIAL', 'Ljava/lang/String;', True, String('null')),
            ]):

    def __init__(self):
        pass

    @staticmethod
    @java_method_def(name='i', signature='(Ljava/lang/String;Ljava/lang/String;)V', native=False)
    def i(mu):
        pass


logger = logging.getLogger(__name__)

# Initialize emulator
emulator = Emulator(
    vfs_root=posixpath.join(posixpath.dirname(__file__), "vfs")
)

# Register Java class.
emulator.java_classloader.add_class(Build)
emulator.java_classloader.add_class(PLog)
emulator.java_classloader.add_class(DeviceNative)

# emulator.mu.hook_add(UC_HOOK_CODE, hook_code, emulator)
# emulator.mu.hook_add(UC_HOOK_MEM_WRITE, hook_mem_write)
# emulator.mu.hook_add(UC_HOOK_MEM_READ, hook_mem_read)

# Load all libraries.
emulator.load_library("tests/bin//libc++_shared.so")
emulator.load_library("tests/bin/libUserEnv.so")
lib_module = emulator.load_library("tests/bin/libPddSecure.so")

# androidemu.utils.debug_utils.dump_symbols(emulator, sys.stdout)

# Show loaded modules.
logger.info("Loaded modules:")

for module in emulator.modules:
    logger.info("=> 0x%08x - %s" % (module.base, module.filename))
    print("=> 0x%08x - %s" % (module.base, module.filename))

try:
    # Run JNI_OnLoad.
    #   JNI_OnLoad will call 'RegisterNatives'.
    emulator.call_symbol(lib_module, 'JNI_OnLoad', emulator.java_vm.address_ptr, 0x00)

    # Do native stuff.
    main_activity = DeviceNative()
    logger.info("Response from JNI call: %s" % main_activity.info2(emulator, 1688005725349))

    # Dump natives found.
    logger.info("Exited EMU.")
    logger.info("Native methods registered to MainActivity:")

except UcError as e:
    print("Exit at %x" % emulator.mu.reg_read(UC_ARM_REG_PC))
    raise
