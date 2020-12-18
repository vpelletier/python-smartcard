# Copyright (C) 2016-2020  Vincent Pelletier <plr.vincent@gmail.com>
#
# This file is part of python-smartcard.
# python-smartcard is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# python-smartcard is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with python-smartcard.  If not, see <http://www.gnu.org/licenses/>.

from .utils import Antipersistent

STATUS_1_NOT_REPORTED                   = 0x00 # Historical bytes only ?
STATUS_1_OK                             = 0x90
STATUS_1_OK_REMAIN                      = 0x61
STATUS_1_WARN_NON_VOLATILE_UNCHANGED    = 0x62
STATUS_2_62_NO_INFORMATION                  = 0x00
STATUS_2_62_RESPONSE_MAY_BE_CORRUPTED       = 0x81
STATUS_2_62_EOF                             = 0x82
STATUS_2_62_FILE_DEACTIVATED                = 0x83
STATUS_2_62_BAD_FILE_CONTROL_FORMAT         = 0x84
STATUS_2_62_FILE_TERMINATED                 = 0x85
STATUS_2_62_NO_SENSOR_INPUT                 = 0x86
STATUS_1_WARN_NON_VOLATILE_CHANGED      = 0x63
STATUS_2_63_NO_INFORMATION                  = 0x00
STATUS_2_63_FILE_FULL                       = 0x81
STATUS_1_ERR_NON_VOLATILE_UNCHANGED     = 0x64
STATUS_2_64_EXECUTION_ERROR                 = 0x00
STATUS_2_64_IMMEDIATE_RESPONSE_REQUIRED     = 0x01
STATUS_1_ERR_NON_VOLATILE_CHANGED       = 0x65
STATUS_2_65_NO_INFORMATION                  = 0x00
STATUS_2_65_MEMORY_FAILURE                  = 0x81
STATUS_1_ERR_SECURITY                   = 0x66
STATUS_1_WRONG_LENGTH                   = 0x67
STATUS_1_CLASS_FUNCTION_UNSUPPORTED     = 0x68
STATUS_2_68_NO_INFORMATION                  = 0x00
STATUS_2_68_LOGICAL_CHANNEL                 = 0x81
STATUS_2_68_SECURE_MESSAGING                = 0x82
STATUS_2_68_CHAIN_EXPECTED_LAST             = 0x83
STATUS_2_68_CHAINING                        = 0x84
STATUS_1_INSTRUCTION_NOT_ALLOWED        = 0x69
STATUS_2_69_NO_INFORMATION                  = 0x00
STATUS_2_69_INCOMPATIBLE_WITH_FILE          = 0x81
STATUS_2_69_SECURITY_NOT_SATISFIED          = 0x82
STATUS_2_69_AUTH_METHOD_BLOCKED             = 0x83
STATUS_2_69_REFERENCE_DATA_NOT_USABLE       = 0x84
STATUS_2_69_CONDITIONS_OF_USE_NOT_SATISFIED = 0x85
STATUS_2_69_NO_CURRENT_ELEMENTARY_FILE      = 0x86
STATUS_2_69_SECURE_DATA_OBJECT_MISSING      = 0x87
STATUS_2_69_SECURE_DATA_OBJECT_INCORRECT    = 0x88
STATUS_1_WRONG_PARAMETERS_P1_P2_DETAIL  = 0x6a
STATUS_2_6A_NO_INFORMATION                  = 0x00
STATUS_2_6A_IN_DATA_FIELD                   = 0x80
STATUS_2_6A_FUNCTION_NOT_SUPPORTED          = 0x81
STATUS_2_6A_FILE_OR_APPLICATION_NOT_FOUND   = 0x82
STATUS_2_6A_RECORD_NOT_FOUND                = 0x83
STATUS_2_6A_NOT_ENOUGH_MEMORY_SPACE_IN_FILE = 0x84
STATUS_2_6A_COMMAND_LEN_INCONSISTENT_TLV    = 0x85
STATUS_2_6A_INCORRECT_P1_P2                 = 0x86
STATUS_2_6A_COMMAND_LEN_INCONSISTENT_P1_P2  = 0x87
STATUS_2_6A_REFERENCE_D_DATA_NOT_FOUND      = 0x88
STATUS_2_6A_FILE_EXISTS                     = 0x89
STATUS_2_6A_DEDICATED_FILE_NAME_EXISTS  = 0x8a
STATUS_1_WRONG_PARAMETERS_P1_P2         = 0x6b
STATUS_1_WRONG_RESPONSE_LENGTH          = 0x6c
STATUS_1_INSTRUCTION_NOT_SUPPORTED      = 0x6d
STATUS_1_CLASS_NOT_SUPPORTED            = 0x6e
STATUS_1_UNSPECIFIED                    = 0x6f

SUCCESS = bytearray((
    STATUS_1_OK,
    0,
))

def successWithMoreResponseBytes(value):
    return bytearray((
        STATUS_1_OK_REMAIN,
        value,
    ))

WARNING = bytearray((
    STATUS_1_WARN_NON_VOLATILE_UNCHANGED,
    STATUS_2_62_NO_INFORMATION,
))

WARNING_RESPONSE_MAY_BE_CORRUPTED = bytearray((
    STATUS_1_WARN_NON_VOLATILE_UNCHANGED,
    STATUS_2_62_RESPONSE_MAY_BE_CORRUPTED,
))

WARNING_EOF = bytearray((
    STATUS_1_WARN_NON_VOLATILE_UNCHANGED,
    STATUS_2_62_EOF,
))

WARNING_FILE_DEACTIVATED = bytearray((
    STATUS_1_WARN_NON_VOLATILE_UNCHANGED,
    STATUS_2_62_FILE_DEACTIVATED,
))

WARNING_BAD_FILE_CONTROL_FORMAT = bytearray((
    STATUS_1_WARN_NON_VOLATILE_UNCHANGED,
    STATUS_2_62_BAD_FILE_CONTROL_FORMAT,
))

WARNING_FILE_TERMINATED = bytearray((
    STATUS_1_WARN_NON_VOLATILE_UNCHANGED,
    STATUS_2_62_FILE_TERMINATED,
))

WARNING_NO_SENSOR_INPUT = bytearray((
    STATUS_1_WARN_NON_VOLATILE_UNCHANGED,
    STATUS_2_62_NO_SENSOR_INPUT,
))

WARNING_PERSISTENT_CHANGED = bytearray((
    STATUS_1_WARN_NON_VOLATILE_CHANGED,
    0,
))

WARNING_FILE_FILLED_BY_LAST_WRITE = bytearray((
    STATUS_1_WARN_NON_VOLATILE_CHANGED,
    STATUS_2_63_FILE_FULL,
))

def warningPersistentChangedCounter(count):
    if not 0 <= count <= 15:
        raise ValueError
    return bytearray((
        STATUS_1_WARN_NON_VOLATILE_CHANGED,
        0xc0 + count,
    ))

class APDUException(Exception, Antipersistent):
    status_1 = STATUS_1_UNSPECIFIED
    status_2 = 0

    @property
    def value(self):
        """
        Encode exception into an APDU status word.
        """
        return bytearray((self.status_1, self.status_2))

class WarnPersistentChanged(APDUException):
    status_1 = STATUS_1_WARN_NON_VOLATILE_CHANGED

    def __init__(self, *args, **kw):
        # Force named argument for remaining
        remaining = kw.pop('remaining')
        super().__init__(*args, **kw)
        self.status_2 = 0xc0 + remaining

class ExecutionError(APDUException):
    pass

class ErrorPersistentUnchanged(ExecutionError):
    status_1 = STATUS_1_ERR_NON_VOLATILE_UNCHANGED
    status_2 = STATUS_2_64_EXECUTION_ERROR

    def __init__(self, *args, **kw):
        # Force named argument for value
        value = kw.pop('value', 0)
        super().__init__(*args, **kw)
        # XXX: wut ?
        if value == STATUS_2_64_IMMEDIATE_RESPONSE_REQUIRED or value > 0x80:
            raise ValueError
        self.status_2 = value

class ErrorPersistentUnchangedImmediateResponseRequired(ErrorPersistentUnchanged):
    status_2 = STATUS_2_64_IMMEDIATE_RESPONSE_REQUIRED

class ErrorPersistentChanged(ExecutionError):
    status_1 = STATUS_1_ERR_NON_VOLATILE_CHANGED
    status_2 = STATUS_2_65_NO_INFORMATION

class ErrorPersistentChangedMemoryFailure(ErrorPersistentChanged):
    status_2 = STATUS_2_65_MEMORY_FAILURE

class SecurityError(ExecutionError):
    status_1 = STATUS_1_ERR_SECURITY

class CheckingError(APDUException):
    pass

class WrongLength(CheckingError):
    status_1 = STATUS_1_WRONG_LENGTH

class ClassFunctionUnsupported(CheckingError):
    status_1 = STATUS_1_CLASS_FUNCTION_UNSUPPORTED
    status_2 = STATUS_2_68_NO_INFORMATION

class ClassLogicalChannelUnsupported(ClassFunctionUnsupported):
    status_2 = STATUS_2_68_LOGICAL_CHANNEL

class ClassSecureMessagingUnsupported(ClassFunctionUnsupported):
    status_2 = STATUS_2_68_SECURE_MESSAGING

class ClassChainContinuationUnsupported(ClassFunctionUnsupported):
    status_2 = STATUS_2_68_CHAIN_EXPECTED_LAST

class ClassChainingUnsupported(ClassFunctionUnsupported):
    status_2 = STATUS_2_68_CHAINING

class InstructionNotAllowed(CheckingError):
    status_1 = STATUS_1_INSTRUCTION_NOT_ALLOWED
    status_2 = STATUS_2_69_NO_INFORMATION

class InstructionIncompatibleWithFile(InstructionNotAllowed):
    status_2 = STATUS_2_69_INCOMPATIBLE_WITH_FILE

class SecurityNotSatisfied(InstructionNotAllowed):
    status_2 = STATUS_2_69_SECURITY_NOT_SATISFIED

class AuthMethodBlocked(InstructionNotAllowed):
    status_2 = STATUS_2_69_AUTH_METHOD_BLOCKED

class ReferenceDataNotUsable(InstructionNotAllowed):
    status_2 = STATUS_2_69_REFERENCE_DATA_NOT_USABLE

class InstructionConditionsOfUseNotSatisfied(InstructionNotAllowed):
    status_2 = STATUS_2_69_CONDITIONS_OF_USE_NOT_SATISFIED

class NoCurrentElementaryFile(InstructionNotAllowed):
    status_2 = STATUS_2_69_NO_CURRENT_ELEMENTARY_FILE

class SecureDataObjectMissing(InstructionNotAllowed):
    status_2 = STATUS_2_69_SECURE_DATA_OBJECT_MISSING

class SecureDataObjectIncorrect(InstructionNotAllowed):
    status_2 = STATUS_2_69_SECURE_DATA_OBJECT_INCORRECT

class WrongParametersP1P2(CheckingError):
    status_1 = STATUS_1_WRONG_PARAMETERS_P1_P2
    status_2 = 0

class WrongParametersP1P2Detail(WrongParametersP1P2):
    status_1 = STATUS_1_WRONG_PARAMETERS_P1_P2_DETAIL
    status_2 = STATUS_2_6A_NO_INFORMATION

class WrongParameterInCommandData(WrongParametersP1P2Detail):
    status_2 = STATUS_2_6A_IN_DATA_FIELD

class ParameterFunctionNotSupported(WrongParametersP1P2Detail):
    status_2 = STATUS_2_6A_FUNCTION_NOT_SUPPORTED

class FileNotFound(WrongParametersP1P2Detail):
    status_2 = STATUS_2_6A_FILE_OR_APPLICATION_NOT_FOUND

class RecordNotFound(WrongParametersP1P2Detail):
    status_2 = STATUS_2_6A_RECORD_NOT_FOUND

class NoSpaceInFile(WrongParametersP1P2Detail):
    status_2 = STATUS_2_6A_NOT_ENOUGH_MEMORY_SPACE_IN_FILE

class CommandDataLengthInconsistentWithTLV(WrongParametersP1P2Detail):
    status_2 = STATUS_2_6A_COMMAND_LEN_INCONSISTENT_TLV

class CommandDataLengthInconsistentWithP1P2(WrongParametersP1P2Detail):
    status_2 = STATUS_2_6A_COMMAND_LEN_INCONSISTENT_P1_P2

class ReferenceDataNotFound(WrongParametersP1P2Detail):
    status_2 = STATUS_2_6A_REFERENCE_D_DATA_NOT_FOUND

class FileExists(WrongParametersP1P2Detail):
    status_2 = STATUS_2_6A_FILE_EXISTS

class DedicatedFileNameExists(WrongParametersP1P2Detail):
    status_2 = STATUS_2_6A_DEDICATED_FILE_NAME_EXISTS

class WrongResponseLength(CheckingError):
    status_1 = STATUS_1_WRONG_RESPONSE_LENGTH

    def __init__(self, *args, **kw):
        # Force named argument for bytes_available
        bytes_available = kw.pop('bytes_available')
        super().__init__(*args, **kw)
        self.status_2 = (
            bytes_available
            if bytes_available < 0x100 else
            0 # Means "256 or more"
        )

class InstructionNotSupported(CheckingError):
    status_1 = STATUS_1_INSTRUCTION_NOT_SUPPORTED

class ClassNotSupported(CheckingError):
    status_1 = STATUS_1_CLASS_NOT_SUPPORTED

class UnspecifiedError(CheckingError):
    status_1 = STATUS_1_UNSPECIFIED
