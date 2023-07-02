"""
com.tesla.easyso1
com.roysue.easyso1
课堂演示OK 不知为何现在结果不对
"""
import logging
import posixpath
import sys

import capstone
import traceback
from unicorn import *
from unicorn.arm_const import *

from androidemu.emulator import Emulator
from androidemu.java.java_class_def import JavaClassDef
from androidemu.java.java_field_def import JavaFieldDef
from androidemu.java.java_method_def import java_method_def
from androidemu.java.classes.string import String
from androidemu.java.classes.types import Long
import androidemu.utils.debug_utils
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


logger = logging.getLogger(__name__)

# Initialize emulator
emulator = Emulator(
    vfs_root=posixpath.join(posixpath.dirname(__file__), "vfs")
)

# Register Java class.
# emulator.java_classloader.add_class(DeviceNative)

# emulator.mu.hook_add(UC_HOOK_CODE, hook_code, emulator)
# emulator.mu.hook_add(UC_HOOK_MEM_WRITE, hook_mem_write)
# emulator.mu.hook_add(UC_HOOK_MEM_READ, hook_mem_read)

# Load all libraries.
# emulator.load_library("vfs/system/lib/libc++_shared.so")
# lib_module = emulator.load_library("tests/bin/libeasyso1.so")
lib_module = emulator.load_library("tests/bin/libroysue.so")

# androidemu.utils.debug_utils.dump_symbols(emulator, sys.stdout)

# Show loaded modules.
logger.info("Loaded modules:")

for module in emulator.modules:
    logger.info("=> 0x%08x - %s" % (module.base, module.filename))
    print("=> 0x%08x - %s" % (module.base, module.filename))

try:
    # Run JNI_OnLoad.
    #   JNI_OnLoad will call 'RegisterNatives'.
    # md5_ret = emulator.call_symbol(lib_module, '_Z3md5PKvj',
    #                                emulator.java_vm.jni_env.address_ptr,
    #                                0x00, String('roysue'))
    encrypt = emulator.call_symbol(lib_module,
                                   # 'Java_com_tesla_easyso1_MainActivity_method01',
                                   'Java_com_roysue_easyso1_MainActivity_method01',
                                   emulator.java_vm.jni_env.address_ptr,
                                   0x00, String('123456'))
    decrypt = emulator.call_symbol(lib_module,
                                   # 'Java_com_tesla_easyso1_MainActivity_method02',
                                   'Java_com_roysue_easyso1_MainActivity_method02',
                                   emulator.java_vm.jni_env.address_ptr,
                                   0x00, encrypt)
    # print('md5_ret', md5_ret)
    print('encrypt', encrypt, 'decrypt', decrypt)
    # print(emulator.mu.reg_read(UC_ARM_REG_R0))  # 9

    # Dump natives found.
    logger.info("Exited EMU.")
    logger.info("Native methods registered to DeviceNative:")

except UcError as e:
    print("Exit at %x" % emulator.mu.reg_read(UC_ARM_REG_PC))
    raise
