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

# pylint: disable=line-too-long, missing-docstring

from collections import defaultdict
import ctypes
import functools
import itertools
import logging
import random
import struct
import persistent
from .asn1 import (
    CLASS_UNIVERSAL,
    AllSchema,
    CodecBER,
    CodecCompact,
    CodecSimple,
    TypeBase,
)
from .tag import (
    AnswerToReset,
    ApplicationExpirationDate,
    ApplicationIdentifier,
    ApplicationLabel,
    ApplicationTemplate,
    CardCapabilities,
    CardLifecycle,
    CardSerialNumber,
    CardServiceData,
    CommandAPDU,
    CURRENT_DEDICATED_FILE,
    CURRENT_ELEMENTARY_FILE,
    DiscretionaryData,
    DiscretionaryTemplate,
    EF_ARR_IDENTIFIER,
    EF_ATR_IDENTIFIER,
    EF_DIR_IDENTIFIER,
    EF_DIR_SHORT_IDENTIFIER,
    EF_GDO_IDENTIFIER,
    ExtendedHeaderList,
    FileChannelSecurity,
    FileControlParametersAndManagementData,
    FileControlParameterTemplate,
    FileDataObjectSecurityProprietary,
    FileDataObjectSecurityTemplate,
    FileDescriptor,
    FileIdentifier,
    FileManagementTemplate,
    FileName,
    FileReference,
    FileSecurityCompactFormat,
    FileSecurityExpandedFormatReference,
    FileSecurityProprietary,
    FileSecurityTemplateExpandedFormat,
    FileSize,
    FileStorageUsage,
    getDataCodingByte,
    getWriteFunctionFromDataCodingByte,
    HistoricalData,
    Lifecycle,
    LifecycleBase,
    MASTER_FILE_IDENTIFIER,
    OffsetData,
    SECURITY_CONDITION_ALLOW,
    SecurityConditionDataObjectList,
    SECURITY_CONDITION_DENY,
    SECURITY_CONDITION_EXTERNAL_AUTHENTICATION,
    SECURITY_CONDITION_LOGICAL_AND,
    SECURITY_CONDITION_LOGICAL_MASK,
    SECURITY_CONDITION_SECURE_MESSAGING,
    SECURITY_CONDITION_SECURITY_ENVIRONMENT_MASK,
    SECURITY_CONDITION_USER_AUTHENTICATION,
    TagHeaderList,
    TagList,
    URL,
    WRITE_FUNCTION_AND,
    WRITE_FUNCTION_ONE_TIME,
    WRITE_FUNCTION_OR,
)
from .status import (
    SUCCESS,
    WARNING_EOF,
    WARNING_FILE_DEACTIVATED,
    WARNING_FILE_TERMINATED,
    APDUException,
    ClassChainContinuationUnsupported,
    ClassLogicalChannelUnsupported,
    ClassNotSupported,
    ClassSecureMessagingUnsupported,
    DedicatedFileNameExists,
    FileExists,
    FileNotFound,
    InstructionConditionsOfUseNotSatisfied,
    InstructionIncompatibleWithFile,
    InstructionNotAllowed,
    InstructionNotSupported,
    NoCurrentElementaryFile,
    NoSpaceInFile,
    ParameterFunctionNotSupported,
    RecordNotFound,
    SecurityNotSatisfied,
    successWithMoreResponseBytes,
    UnspecifiedError,
    WrongLength,
    WrongParameterInCommandData,
    WrongParametersP1P2,
)
from .utils import (
    chainBytearrayList,
    Antipersistent,
    PersistentWithVolatileSurvivor,
    transaction_manager,
    bitpos,
    bitcount,
)

logger = logging.getLogger(__name__)

def encodeBEInteger(value):
    """
    Serialise an integer of arbitrary length into a big-endian representation.
    """
    bit_length = value.bit_length()
    byte_length = bit_length >> 3
    if bit_length & 0x7:
        byte_length += 1
    return value.to_bytes(byte_length, 'big')

assert encodeBEInteger(0x1234) == b'\x12\x34'

def _xor(byte_value):
    """
    Return the XOR of all bytes in given value.
    """
    result = 0
    for item in byte_value:
        result ^= item
    return result

@functools.total_ordering
class APDUHead(ctypes.Structure, Antipersistent):
    """
    Structure of an Application Protocol Data Unit fixed-size header.
    """
    _pack_ = 1
    _fields_ = [
        ('klass', ctypes.c_ubyte),
        ('instruction', ctypes.c_ubyte),
        ('parameter1', ctypes.c_ubyte),
        ('parameter2', ctypes.c_ubyte),
    ]

    def __eq__(self, other):
        return (
            self.klass == getattr(other, 'klass', None) and
            self.instruction == getattr(other, 'instruction', None) and
            self.parameter1 == getattr(other, 'parameter1', None) and
            self.parameter2 == getattr(other, 'parameter2', None)
        )

    def __lt__(self, other):
        return NotImplemented

APDU_HEAD_LENGTH = ctypes.sizeof(APDUHead)

def dumpAPDUHead(head):
    if head is None:
        return 'None'
    return 'class=%02x instruction=%02x p1=%02x p2=%02x' % (
        head.klass,
        head.instruction,
        head.parameter1,
        head.parameter2,
    )

CLASS_TYPE_MASK = 0x80
CLASS_TYPE_PROPRIETARY = 0x80
CLASS_TYPE_STANDARD = 0x00
# CLASS_STANDARD_FIRST is a terrible name
CLASS_STANDARD_FIRST_MASK = 0xe0
CLASS_STANDARD_FIRST = 0x00
CLASS_STANDARD_FIRST_CHAINING_MASK = 0x10
CLASS_STANDARD_FIRST_CHAINING_FINAL = 0x00
CLASS_STANDARD_FIRST_CHAINING_NON_FINAL = 0x10
CLASS_STANDARD_FIRST_SECURE_MASK = 0x0c
CLASS_STANDARD_FIRST_SECURE_NONE = 0x00
CLASS_STANDARD_FIRST_SECURE_PROPRIETARY = 0x04
CLASS_STANDARD_FIRST_SECURE_STANDARD_UNAUTH_HEAD = 0x08
CLASS_STANDARD_FIRST_SECURE_STANDARD_AUTH_HEAD = 0x0c
CLASS_STANDARD_FIRST_CHAN_MASK = 0x03
# CLASS_STANDARD_FURTHER is a terrible name
CLASS_STANDARD_FURTHER_MASK = 0xc0
CLASS_STANDARD_FURTHER = 0x40
CLASS_STANDARD_FURTHER_SECURE_MASK = 0x20
CLASS_STANDARD_FURTHER_SECURE_NONE = 0x00
CLASS_STANDARD_FURTHER_SECURE_STANDARD_UNAUTH_HEAD = 0x20
CLASS_STANDARD_FURTHER_CHAINING_MASK = 0x10
CLASS_STANDARD_FURTHER_CHAINING_FINAL = 0x00
CLASS_STANDARD_FURTHER_CHAINING_NOT_FINAL = 0x10
CLASS_STANDARD_FURTHER_CHAN_MASK = 0x0f

SECURE_NONE = object()
SECURE_PROPRIETARY = object()
SECURE_STANDARD_UNAUTH_HEAD = object()
SECURE_STANDARD_AUTH_HEAD = object()
CLASS_STANDARD_FIRST_SECURE_DICT = {
    CLASS_STANDARD_FIRST_SECURE_NONE: SECURE_NONE,
    CLASS_STANDARD_FIRST_SECURE_PROPRIETARY: SECURE_PROPRIETARY,
    CLASS_STANDARD_FIRST_SECURE_STANDARD_UNAUTH_HEAD: SECURE_STANDARD_UNAUTH_HEAD,
    CLASS_STANDARD_FIRST_SECURE_STANDARD_AUTH_HEAD: SECURE_STANDARD_AUTH_HEAD,
}
CLASS_STANDARD_FURTHER_SECURE_DICT = {
    CLASS_STANDARD_FURTHER_SECURE_NONE: SECURE_NONE,
    CLASS_STANDARD_FURTHER_SECURE_STANDARD_UNAUTH_HEAD: SECURE_STANDARD_UNAUTH_HEAD,
}

INSTRUCTION_BERTLV_MASK = 0x01
INSTRUCTION_BERTLV = 0x01

INSTRUCTION_ERASE_RECORD = 0x0c
INSTRUCTION_ERASE_BINARY = 0x0e
INSTRUCTION_VERIFY = 0x20
INSTRUCTION_MANAGE_SECURITY_ENVIRONMENT = 0x22
INSTRUCTION_MANAGE_SECURITY_ENVIRONMENT_P1_SET_ACTION_MASK = 0x0f
INSTRUCTION_MANAGE_SECURITY_ENVIRONMENT_P1_SET = 0x01
INSTRUCTION_MANAGE_SECURITY_ENVIRONMENT_P1_SET_SUBJECT_MASK = 0xf0
INSTRUCTION_MANAGE_SECURITY_ENVIRONMENT_P1_SET_SUBJECT_SECURE_MESSAGING_COMMAND = 0x10
INSTRUCTION_MANAGE_SECURITY_ENVIRONMENT_P1_SET_SUBJECT_SECURE_MESSAGING_RESPONSE = 0x20
INSTRUCTION_MANAGE_SECURITY_ENVIRONMENT_P1_SET_SUBJECT_DECIPHER = 0x40
INSTRUCTION_MANAGE_SECURITY_ENVIRONMENT_P1_SET_SUBJECT_ENCIPHER = 0x80
INSTRUCTION_MANAGE_SECURITY_ENVIRONMENT_P1_STORE = 0xf2
INSTRUCTION_MANAGE_SECURITY_ENVIRONMENT_P1_RESTORE = 0xf3
INSTRUCTION_MANAGE_SECURITY_ENVIRONMENT_P1_ERASE = 0xf4
INSTRUCTION_CHANGE_REFERENCE_DATA = 0x24
INSTRUCTION_DISABLE_VERIFICATION_REQUIREMENT = 0x26
INSTRUCTION_ENABLE_VERIFICATION_REQUIREMENT = 0x28
INSTRUCTION_RESET_RETRY_COUNTER = 0x2c
INSTRUCTION_MANAGE_CHANNEL = 0x70
# 0x80 for flag, but the whole byte is reserved
INSTRUCTION_MANAGE_CHANNEL_P1_ACTION_MASK = 0xff
INSTRUCTION_MANAGE_CHANNEL_P1_ACTION_OPEN = 0x00
INSTRUCTION_MANAGE_CHANNEL_P1_ACTION_CLOSE = 0x80
INSTRUCTION_EXTERNAL_AUTHENTICATE = 0x82
INSTRUCTION_GET_CHALLENGE = 0x84
INSTRUCTION_GENERAL_AUTHENTICATE = 0x86
INSTRUCTION_INTERNAL_AUTHENTICATE = 0x88
INSTRUCTION_SEARCH_BINARY = 0xa0
INSTRUCTION_SEARCH_RECORD = 0xa2
INSTRUCTION_SELECT = 0xa4
INSTRUCTION_SELECT_P1_ANY = 0x00
INSTRUCTION_SELECT_P1_CHILD_DEDICATED_FILE = 0x01
INSTRUCTION_SELECT_P1_CHILD_ELEMENTARY_FILE = 0x02
INSTRUCTION_SELECT_P1_PARENT = 0x03
INSTRUCTION_SELECT_P1_BY_NAME = 0x04
INSTRUCTION_SELECT_P1_BY_ABSOLUTE_PATH = 0x08
INSTRUCTION_SELECT_P1_BY_RELATIVE_PATH = 0x09
INSTRUCTION_SELECT_P2_WHENCE_MASK = 0x03
INSTRUCTION_SELECT_P2_WHENCE_FIRST = 0x00
INSTRUCTION_SELECT_P2_WHENCE_LAST = 0x01
INSTRUCTION_SELECT_P2_WHENCE_NEXT = 0x02
INSTRUCTION_SELECT_P2_WHENCE_PREVIOUS = 0x03
INSTRUCTION_SELECT_P2_RETURN_MASK = 0x0c
INSTRUCTION_SELECT_P2_RETURN_FILE_CONTROL_INFORMATION = 0x00
INSTRUCTION_SELECT_P2_RETURN_FILE_CONTROL_PARAMETER = 0x04
INSTRUCTION_SELECT_P2_RETURN_FILE_MANAGEMENT_DATA = 0x08
INSTRUCTION_SELECT_P2_RETURN_PROPRIETARY = 0x0c
INSTRUCTION_READ_BINARY = 0xb0
INSTRUCTION_READ_RECORD = 0xb2
INSTRUCTION_READ_RECORD_P2_SHORT_ELEMENTARY_FILE_IDENTIFIER_MASK = 0xf8
INSTRUCTION_READ_RECORD_P2_P1_IS_RECORD_NUMBER = 0x04
INSTRUCTION_READ_RECORD_P2_RANGE_MASK = 0x03
INSTRUCTION_READ_RECORD_P2_RECORD_NUMBER_RANGE_SINGLE = 0x00
INSTRUCTION_READ_RECORD_P2_RECORD_NUMBER_RANGE_FROM = 0x01
INSTRUCTION_READ_RECORD_P2_RECORD_NUMBER_RANGE_TO = 0x02
INSTRUCTION_READ_RECORD_P2_IDENTIFIER_RANGE_FIRST = 0x00
INSTRUCTION_READ_RECORD_P2_IDENTIFIER_RANGE_LAST = 0x01
INSTRUCTION_READ_RECORD_P2_IDENTIFIER_RANGE_NEXT = 0x02
INSTRUCTION_READ_RECORD_P2_IDENTIFIER_RANGE_PREVIOUS = 0x03
INSTRUCTION_GET_RESPONSE = 0xc0
INSTRUCTION_ENVELOPE = 0xc2
INSTRUCTION_GET_DATA = 0xca
INSTRUCTION_GET_NEXT_DATA = 0xcc
INSTRUCTION_WRITE_BINARY = 0xd0
INSTRUCTION_WRITE_RECORD = 0xd2
INSTRUCTION_UPDATE_BINARY = 0xd6
INSTRUCTION_PUT_DATA = 0xda
INSTRUCTION_UPDATE_RECORD = 0xdc
INSTRUCTION_APPEND_RECORD = 0xe2
INSTRUCTION_PERFORM_SECURIY_OPERATION = 0x2a
INSTRUCTION_GENERATE_ASYMMETRIC_KEY_PAIR = 0x46
INSTRUCTION_DEACTIVATE_FILE = 0x04
INSTRUCTION_ACTIVATE_FILE = 0x44
INSTRUCTION_CREATE_FILE = 0xe0
INSTRUCTION_DELETE_FILE = 0xe4
INSTRUCTION_TERMINATE_DEDICATED_FILE = 0xe6
INSTRUCTION_TERMINATE_ELEMENTARY_FILE = 0xe8
INSTRUCTION_TERMINATE_CARD = 0xfe

# Instructions which may have the INSTRUCTION_BERTLV bit set
BERTLV_SUPPORT_SET = (
    INSTRUCTION_ERASE_BINARY,
    INSTRUCTION_VERIFY,
    INSTRUCTION_GENERAL_AUTHENTICATE,
    INSTRUCTION_SEARCH_BINARY,
    INSTRUCTION_READ_BINARY,
    INSTRUCTION_READ_RECORD,
    INSTRUCTION_ENVELOPE,
    INSTRUCTION_GET_DATA,
    INSTRUCTION_GET_NEXT_DATA,
    INSTRUCTION_WRITE_BINARY,
    INSTRUCTION_UPDATE_BINARY,
    INSTRUCTION_PUT_DATA,
    INSTRUCTION_UPDATE_RECORD,
    INSTRUCTION_GENERATE_ASYMMETRIC_KEY_PAIR,
)

# All instructions which need to be run on an open channel (so all but SELECT).
# XXX: not pythonic...
INSTRUCTION_METHOD_ID_DICT = {
    INSTRUCTION_ERASE_RECORD: 'handleEraseRecord',                                              #
    INSTRUCTION_ERASE_BINARY: 'handleEraseBinary',                                              # Done
    INSTRUCTION_VERIFY: 'handleVerify',                                                         # Done~
    INSTRUCTION_MANAGE_SECURITY_ENVIRONMENT: 'handleManageSecurityEnvironment',                 # Done~
    INSTRUCTION_CHANGE_REFERENCE_DATA: 'handleChangeReferenceData',                             # Done~
    INSTRUCTION_DISABLE_VERIFICATION_REQUIREMENT: 'handleDisableVerificationRequirement',       #
    INSTRUCTION_ENABLE_VERIFICATION_REQUIREMENT: 'handleEnableVerificationRequirement',         #
    INSTRUCTION_RESET_RETRY_COUNTER: 'handleResetRetryCounter',                                 # Done? (pgp spec only)
    INSTRUCTION_MANAGE_CHANNEL: 'handleManageChannel',                                          # Done
    INSTRUCTION_EXTERNAL_AUTHENTICATE: 'handleExternalAuthenticate',                            #
    INSTRUCTION_GET_CHALLENGE: 'handleGetChallenge',                                            # Done
    INSTRUCTION_GENERAL_AUTHENTICATE: 'handleGeneralAuthenticate',                              #
    INSTRUCTION_INTERNAL_AUTHENTICATE: 'handleInternalAuthenticate',                            # Done~
    INSTRUCTION_SEARCH_BINARY: 'handleSearchBinary',                                            # Done
    INSTRUCTION_SEARCH_RECORD: 'handleSearchRecord',                                            #
#    INSTRUCTION_SELECT: 'handleSelect',                                                        # Done
    INSTRUCTION_READ_BINARY: 'handleReadBinary',                                                # Done
    INSTRUCTION_READ_RECORD: 'handleReadRecord',                                                #
#    INSTRUCTION_GET_RESPONSE: 'handleGetResponse',                                             # Done
#    INSTRUCTION_ENVELOPE: 'handleEnvelope',                                                    # Done
    INSTRUCTION_GET_DATA: 'handleGetData',                                                      # Done
    INSTRUCTION_GET_NEXT_DATA: 'handleGetNextData',                                             # Done~
    INSTRUCTION_WRITE_BINARY: 'handleWriteBinary',                                              # Done
    INSTRUCTION_UPDATE_BINARY: 'handleUpdateBinary',                                            # Done
    INSTRUCTION_PUT_DATA: 'handlePutData',                                                      # Done
    INSTRUCTION_UPDATE_RECORD: 'handleUpdateRecord',                                            #
    INSTRUCTION_APPEND_RECORD: 'handleAppendRecord',                                            #
    INSTRUCTION_PERFORM_SECURIY_OPERATION: 'handlePerformSecurityOperation',                    # Done~
    INSTRUCTION_GENERATE_ASYMMETRIC_KEY_PAIR: 'handleGenerateAsymmetricKeyPair',                # Done~
    INSTRUCTION_DEACTIVATE_FILE: 'handleDeactivateFile',                                        # Done~
    INSTRUCTION_ACTIVATE_FILE: 'handleActivateFile',                                            # Done~
    INSTRUCTION_CREATE_FILE: 'handleCreateFile',                                                #
    INSTRUCTION_DELETE_FILE: 'handleDeleteFile',                                                #
    INSTRUCTION_TERMINATE_DEDICATED_FILE: 'handleTerminateDedicatedFile',                       # Done~
    INSTRUCTION_TERMINATE_ELEMENTARY_FILE: 'handleTerminateElementaryFile',                     # Done~
    INSTRUCTION_TERMINATE_CARD: 'handleTerminateCard',                                          # Done~
}

ALL_INSTRUCTION_DICT = INSTRUCTION_METHOD_ID_DICT.copy()
ALL_INSTRUCTION_DICT[INSTRUCTION_GET_RESPONSE] = 'handleGetResponse'
ALL_INSTRUCTION_DICT[INSTRUCTION_ENVELOPE] = 'handleEnvelope'
ALL_INSTRUCTION_DICT[INSTRUCTION_SELECT] = 'handleSelect'

HISTORICAL_BYTES_CATEGORY_STATUS_RAW = 0x00
HISTORICAL_BYTES_CATEGORY_DIR_DATA_REFERENCE = 0x10
HISTORICAL_BYTES_CATEGORY_STATUS_COMPACT_TLV = 0x80

class SecurityNoMatch(Exception, Antipersistent):
    """
    No security definition is applicable, apply some default.
    """

BASIC_SECURITY_P1_NO_INFORMATION = 0x00
BASIC_SECURITY_P1_LOGOUT = 0xff # XXX: openpgp app only ?
BASIC_SECURITY_P2_RESERVED_MASK = 0x60
BASIC_SECURITY_P2_SCOPE_MASK = 0x80
BASIC_SECURITY_P2_SCOPE_GLOBAL = 0x00
BASIC_SECURITY_P2_SCOPE_LOCAL = 0x80
BASIC_SECURITY_P2_QUALIFIER_MASK = 0x1f

def decodeAPDU(command):
    """
    Decode an APDU command into:
    - APDUHead instance
    - command data bytes
    - response length (excluding the 2 status bytes)
    """
    trailer = memoryview(command)[APDU_HEAD_LENGTH:]
    if trailer:
        # Abandon all hope, ye who enter here.
        # All we do here is extract parameter data and how many bytes are
        # expected in response. And the format is trying way too hard to
        # use every single bit, which is completely anachronic and causes
        # such massive unreadable bug nest.

        # Assume there is a command length.
        command_len = trailer[0]
        if command_len == 0 and len(trailer) > 1:
            # command length is zero but there is something after: this is the
            # mark of an extended length (2 bytes, big-endian).
            command_len = (trailer[1] << 8) + trailer[2]
            trailer = trailer[3:]
            has_extended_command_len = True
        else:
            trailer = trailer[1:]
            has_extended_command_len = False
        if trailer:
            # There is more data, so it was indeed the command length.
            # Pull the command data from the trailer.
            command_data = trailer[:command_len]
            if len(command_data) != command_len:
                raise WrongLength('short command read')
            # Now look for a response length.
            trailer = trailer[command_len:]
            trailer_len = len(trailer)
            if trailer_len == 0:
                # No response length given, response length is zero.
                response_len = 0
            elif trailer_len == 1:
                # Single-byte response length, with 0 meaning 256.
                if has_extended_command_len:
                    raise WrongLength('Lc is extended, Le is short')
                response_len = trailer[0]
                if response_len == 0:
                    response_len = 256
            elif trailer_len == 2:
                # Extended response length (2 bytes, big-endian), with 0
                # meaning 65536.
                if not has_extended_command_len:
                    raise WrongLength('Lc is short, Le is extended')
                response_len = (trailer[0] << 8) + trailer[1]
                if response_len == 0:
                    response_len = 65536
            else:
                raise WrongLength('too much data left:', trailer_len)
        else:
            # There is no data after the assumed command length: this was
            # response length after all.
            command_data = trailer
            response_len = command_len
    else:
        command_data = trailer
        response_len = 0
    return APDUHead.from_buffer(command), command_data, response_len

class ProxyFile(Antipersistent):
    """
    Represents a file within the context of the path used to access it.
    """
    def __init__(self, path_list, real_file):
        super().__init__()
        self._path_list = path_list
        self._real_file = real_file

    def __repr__(self):
        return '<%s(path_list=%r, real_file=%r) object at %x>' % (
            self.__class__.__name__,
            self._path_list,
            self._real_file,
            id(self),
        )

    def isinstance(self, klass):
        return isinstance(self._real_file, klass)

    def iterPath(self, channel):
        yield self
        traverse = channel.traverse
        path_list = self._path_list
        for tail_length in range(1, len(path_list)):
            yield traverse(path_list[-tail_length])

    def __rejectIfTerminated(self, channel):
        """
        Reject if any parent is terminated.
        """
        for parent_file in self.iterPath(channel=channel):
            if (
                parent_file.lifecycle & LifecycleBase.TERMINATED_MASK
            ) == LifecycleBase.TERMINATED:
                raise SecurityNotSatisfied('terminated: %r' % (parent_file, ))

    def __fallbackSecurity(self, reason):
        """
        If no security applies to requested operation, it is permitted until
        operational.
        """
        if self._real_file.lifecycle not in (
            LifecycleBase.CREATION,
            LifecycleBase.INITIALISATION,
        ):
            raise SecurityNotSatisfied('fallback security: %r' % (reason, ))

    def validate(self, channel, permission, apdu_head):
        self.__rejectIfTerminated(channel=channel)
        try:
            return self._real_file.validate(
                channel=channel,
                permission=permission,
                apdu_head=apdu_head,
                _from_proxy=True,
            )
        except SecurityNoMatch as exc:
            self.__fallbackSecurity('validate: no match for %r: %r' % (permission, exc))

    def validateDataObjectAccess(
        self,
        channel,
        tag_set,
        permission,
        apdu_head,
    ):
        self.__rejectIfTerminated(channel=channel)
        try:
            return self._real_file.validateDataObjectAccess(
                channel=channel,
                tag_set=tag_set,
                permission=permission,
                apdu_head=apdu_head,
                _from_proxy=True,
            )
        except SecurityNoMatch as exc:
            self.__fallbackSecurity('validateDataObjectAccess: no match for %r %r: %r' % (permission, tag_set, exc))

    def __getattr__(self, name):
        return getattr(self._real_file, name)

class BaseFile(persistent.Persistent):
    def __init__(
        self,
        file_type,
        identifier,
        lifecycle=LifecycleBase.CREATION,
        shared=False,
        structure=None,
        data_coding_byte=None,
        record_length=None,
        record_count=None,
    ):
        super().__init__()
        if not isinstance(identifier, bytes) or len(identifier) != 2:
            raise ValueError('identifier is not 2 bytes')
        if identifier == CURRENT_DEDICATED_FILE:
            raise ValueError('identifier %s is reserved' % (identifier.hex(), ))
        self.__identifier = identifier
        self.__lifecycle = Lifecycle.encode(lifecycle, codec=CodecBER)
        self.__file_descriptor_data_object_base = FileDescriptor.encode(
            value={
                'shareable': shared,
                'file_type': file_type,
                'structure': structure,
                'data_coding_byte': data_coding_byte,
                'record_length': record_length,
                'record_count': record_count,
            },
            codec=CodecBER,
        )
        self.__data_object_dict = persistent.mapping.PersistentMapping()
        self.__blank()

    def blank(self):
        self.__data_object_dict.clear()
        self.__blank()

    def __blank(self):
        self.putData(FileIdentifier, self.__identifier, encode=False)
        self.putData(Lifecycle, self.__lifecycle, encode=False)

    def __repr__(self):
        return '<%s(identifier=%r, lifecycle=%r) object at %x>' % (
            self.__class__.__name__,
            self.identifier,
            self.lifecycle,
            id(self),
        )

    def iterPath(self, *_, **__):
        raise RuntimeError('Not a ProxyFile')

    def isinstance(self, *_, **__):
        raise RuntimeError('Not a ProxyFile')

    def validate(self, channel, permission, apdu_head, _from_proxy):
        assert _from_proxy is True
        getData = self.getData
        value = getData(FileChannelSecurity)
        if value is not None:
            channel.validateChannelSecurity(channel_security=value)
        validate = channel.validate
        satisfied = False
        for tag, value in self.iterData(
            tag_list=(
                FileSecurityExpandedFormatReference,
                FileSecurityCompactFormat,
                FileSecurityTemplateExpandedFormat,
                FileSecurityProprietary,
            ),
            decode=True,
        ):
            assert value is not None, (tag, value)
            try:
                validate(
                    permission=permission,
                    apdu_head=apdu_head,
                    tag=tag,
                    value=value,
                )
            except SecurityNoMatch:
                pass
            else:
                satisfied = True
                break
        if not satisfied:
            raise SecurityNoMatch

    def _iterDataObjectSecurity(self):
        decode = CodecBER.decode
        schema_0 = next(FileDataObjectSecurityTemplate.iterItemSchema()) # pylint: disable=stop-iteration-return
        schema_1 = {TagList.asTagTuple(): TagList}
        value = self.getData(
            FileDataObjectSecurityTemplate,
            decode=False,
        )
        while value:
            rule_tag, rule_value, value = decode(value, schema=schema_0)
            _, applicable_tag_list, value = decode(value, schema=schema_1)
            yield (rule_tag, rule_value), applicable_tag_list

    def _getDataObjectSecurityAsDict(self):
        result = defaultdict(set)
        for security, tag_list in self._iterDataObjectSecurity():
            for tag in tag_list:
                result[tag].add(security)
        return result

    def setDataObjectSecurityDict(self, data_object_security_dict):
        """
        Replace the whole current data object security template.
        """
        per_security_dict = defaultdict(list)
        schema = next(FileDataObjectSecurityTemplate.iterItemSchema())
        encode = CodecBER.encode
        for (
            applicable_tag,
            security_set,
        ) in data_object_security_dict.items():
            for security_tag, security_value in security_set:
                if security_tag.asTagTuple() not in schema:
                    raise ValueError('Invalid security rule tag %r for access to %r' % (
                        security_tag,
                        applicable_tag,
                    ))
                key = encode(
                    tag=security_tag,
                    value=security_value,
                )
                per_security_dict[key].append(applicable_tag)
        self.putData(
            tag=FileDataObjectSecurityTemplate,
            value=b''.join(
                security + encode(
                    tag=TagList,
                    value=applicable_tag_list,
                )
                for (
                    security,
                    applicable_tag_list,
                ) in per_security_dict.items()
            ),
            index=0,
            encode=False,
        )

    def setDataObjectSecurityForTag(self, tag, security_set):
        """
        security_set (None or iterable)
            If None, remove security definition from this Data Object.
            Otherwise, it must be an iterable producing pairs:
            - a security tag:
              TAG_FILE_SECURITY_EXPANDED_FORMAT_REFERENCE
              TAG_FILE_SECURITY_COMPACT_FORMAT
              TAG_FILE_SECURITY_TEMPLATE_EXPANDED_FORMAT
              TAG_FILE_CHANNEL_SECURITY
              TAG_FILE_SECURITY_PROPRIETARY_FORMAT
              TAG_FILE_DATA_OBJECT_SECURITY_PROPRIETARY
            - its content (type-dependent)
        """
        security_dict = self._getDataObjectSecurityAsDict()
        if security_set:
            security_dict[tag] = security_set
        else:
            security_dict.pop(tag, None)
        self.setDataObjectSecurityDict(security_dict)

    def validateDataObjectAccess(
        self,
        channel,
        tag_set,
        permission,
        apdu_head,
        _from_proxy,
    ):
        assert _from_proxy
        tag_set = set(tag_set)
        validate = channel.validate
        for (
            security_tag,
            security_value,
        ), tag_list in self._iterDataObjectSecurity():
            relevant_tag_set = tag_set.intersection(tag_list)
            if relevant_tag_set:
                try:
                    validate(
                        permission=permission,
                        apdu_head=apdu_head,
                        tag=security_tag,
                        value=security_value,
                    )
                except SecurityNoMatch:
                    pass
                else:
                    # It's ok for these tags
                    tag_set -= relevant_tag_set
                    if not tag_set:
                        # And we are done.
                        return
        if tag_set:
            raise SecurityNoMatch(tag_set)

    @property
    def _dynamicGetDataObjectDict(self):
        return {
            FileSize: '_getFileSize',
            FileStorageUsage: '_getFileUsage',
            FileDescriptor: '_getTagFileDescriptor',
            # XXX: more ?
        }

    @property
    def _dynamicSetDataObjectDict(self):
        return {}

    def _putData(self, tag, value, index=None):
        if not isinstance(value, bytes):
            raise TypeError(type(value))
        tag_tuple = tag.asTagTuple()
        try:
            object_list = self.__data_object_dict[tag_tuple]
        except KeyError:
            object_list = self.__data_object_dict[tag_tuple] = persistent.list.PersistentList()
        if index is None:
            if object_list:
                raise ValueError('already set')
            index = 0
        if index == len(object_list):
            object_list.append(value)
        else:
            object_list[index] = value

    def putData(self, tag, value, index=None, encode=False):
        if encode:
            value = tag.encode(value, codec=CodecBER)
        if not isinstance(value, bytes):
            raise TypeError(type(value))
        setter_id = self._dynamicSetDataObjectDict.get(tag)
        if setter_id is None:
            if tag in self._dynamicGetDataObjectDict:
                # Forbid putting an object which has a dynamic getter but no
                # dynamic setter.
                raise ParameterFunctionNotSupported
            self._putData(tag=tag, value=value, index=index)
        else:
            getattr(self, setter_id)(value=value, index=index)

    def getData(self, tag, index=None, decode=False):
        getter_id = self._dynamicGetDataObjectDict.get(tag)
        if getter_id is None:
            value = self.__data_object_dict.get(tag.asTagTuple())
        else:
            value = getattr(self, getter_id)()
        if value is not None:
            if index is None:
                try:
                    value, = value
                except ValueError:
                    raise RecordNotFound from None
            else:
                try:
                    value = value[index]
                except IndexError:
                    raise RecordNotFound from None
            if not isinstance(value, bytes):
                raise TypeError(type(value))
            if decode:
                value = tag.decode(value, codec=CodecBER)
        return value

    def iterData(self, tag_list=None, decode=False):
        process = (
            lambda tag, value: tag.decode(value, codec=CodecBER)
            if decode else
            lambda tag, value: value
        )
        if tag_list:
            get = self.__data_object_dict.get
            dynamic_get = self._dynamicGetDataObjectDict.get
            for tag in tag_list:
                getter_id = dynamic_get(tag)
                if getter_id is None:
                    value_list = get(tag.asTagTuple(), ())
                else:
                    value_list = getattr(self, getter_id)()
                for value in value_list:
                    yield tag, process(tag, value)
        else:
            for tag_tuple, value_list in self.__data_object_dict.items():
                tag = AllSchema[tag_tuple]
                for value in value_list:
                    yield tag, value
            for tag, getter_id in self._dynamicGetDataObjectDict.items():
                value_list = getattr(self, getter_id)()
                for value in value_list:
                    yield tag, process(tag, value)

    def _getTagFileDescriptor(self):
        return (self.__file_descriptor_data_object_base, )

    def _getFileSize(self):
        return (bytes((self.getFileSize(), )), )

    def _getFileUsage(self):
        return (bytes((self.getFileUsage(), )), )

    def getFileSize(self):
        return 0

    def getFileUsage(self):
        return self.getFileSize()

    @property
    def identifier(self):
        return self.getData(FileIdentifier, decode=False)

    @property
    def exclusive(self):
        # XXX: can be present in whatever setDataObjectSecurityDict sets ?
        channel_security = self.getData(FileChannelSecurity, decode=True)
        if channel_security is not None:
            return bool(channel_security & FileChannelSecurity.EXCLUSIVE)
        return False

    @property
    def lifecycle(self):
        return self.getData(Lifecycle, decode=True)

    def terminate(self, channel):
        _ = channel # silence pylint
        self.terminateSelf()

    def terminateSelf(self):
        self.putData(Lifecycle, LifecycleBase.TERMINATED, index=0, encode=True)

    def activate(self, channel):
        _ = channel # silence pylint
        self.activateSelf()

    def activateSelf(self):
        self.putData(Lifecycle, LifecycleBase.ACTIVATED, index=0, encode=True)

    def deactivate(self, channel):
        _ = channel # silence pylint
        self.deactivateSelf()

    def deactivateSelf(self):
        self.putData(Lifecycle, LifecycleBase.DEACTIVATED, index=0, encode=True)

class ElementaryFile(BaseFile):
    def __init__(self, internal, **kw):
        super().__init__(
            file_type=(
                FileDescriptor.FILE_TYPE_ELEMENTARY_INTERNAL
                if internal else
                FileDescriptor.FILE_TYPE_ELEMENTARY_WORKING
            ),
            **kw
        )

    def validate(self, channel, permission, apdu_head, _from_proxy):
        if self.getData(
            FileDescriptor,
            decode=True,
        )['file_type'] is FileDescriptor.FILE_TYPE_ELEMENTARY_INTERNAL:
            raise SecurityNotSatisfied('file is internal') # ...and cannot be
        super().validate(
            channel=channel,
            permission=permission,
            apdu_head=apdu_head,
            _from_proxy=_from_proxy,
        )

    def setStandardCompactSecurity(
        self,
        read=SECURITY_CONDITION_DENY,
        modify=SECURITY_CONDITION_DENY,
        extend=SECURITY_CONDITION_DENY,
        deactivate=SECURITY_CONDITION_DENY,
        activate=SECURITY_CONDITION_DENY,
        terminate=SECURITY_CONDITION_DENY,
        delete=SECURITY_CONDITION_DENY,
    ):
        self.putData(
            FileSecurityCompactFormat,
            {
                FileSecurityCompactFormat.READ:        read,
                FileSecurityCompactFormat.MODIFY:      modify,
                FileSecurityCompactFormat.EXTEND:      extend,
                FileSecurityCompactFormat.DEACTIVATE:  deactivate,
                FileSecurityCompactFormat.ACTIVATE:    activate,
                FileSecurityCompactFormat.TERMINATE:   terminate,
                FileSecurityCompactFormat.DELETE_SELF: delete,
            },
            index=0,
            encode=True,
        )

WRITE_MODE_REPLACE = object()
WRITE_MODE_ONCE = object()
WRITE_MODE_OR = object()
WRITE_MODE_AND = object()
WRITE_MODE_XOR = object()

WRITE_MODE_DICT = {
    WRITE_MODE_OR: lambda current, is_allocated, new: (
        current | new if is_allocated else new
    ),
    WRITE_MODE_AND: lambda current, is_allocated, new: (
        current & new if is_allocated else new
    ),
    WRITE_MODE_XOR: lambda current, is_allocated, new: (
        current ^ new if is_allocated else new
    ),
}

WRITE_BEHAVIOUR_TO_MODE_DICT = {
    WRITE_FUNCTION_ONE_TIME: WRITE_MODE_ONCE,
    WRITE_FUNCTION_OR: WRITE_MODE_OR,
    WRITE_FUNCTION_AND: WRITE_MODE_AND,
}

# TODO: support larger data units than bytes ?
class TransparentElementaryFile(ElementaryFile):
    def __init__(self, length, **kw):
        super().__init__(
            structure=FileDescriptor.STRUCTURE_EF_TRANSPARENT,
            **kw
        )
        self.__length = length
        self.__blank()

    def blank(self):
        super().blank()
        self.__blank()

    def __blank(self):
        bitmap_length, remain = divmod(self.__length, 8)
        self.__bitmap = bytearray(bitmap_length + (1 if remain else 0))
        self.__data = bytearray(self.__length)

    def getFileSize(self):
        return len(self.__data)

    def getFileUsage(self):
        return len(self.__data) + len(self.__bitmap)

    def _updateBitmapRange(self, allocate, offset, length):
        # For some reason, "assert self._p_changed" raises *and* segfaults
        self._p_changed = True
        bitmap = self.__bitmap
        first_offset, first_bit_index = divmod(offset, 8)
        last_offset, last_bit_index = divmod(offset + length - 1, 8)
        first_mask = 0xff >> (8 - first_bit_index)
        last_mask = 0xff << last_bit_index
        if allocate:
            first_mask = 0xff & ~first_mask
            last_mask = 0xff & ~last_mask
        if first_offset == last_offset:
            if allocate:
                bitmap[first_offset] |= (first_mask | last_mask)
            else:
                bitmap[first_offset] &= (first_mask | last_mask)
        else:
            if allocate:
                bitmap[first_offset] |= first_mask
                bitmap[last_offset] |= last_mask
            else:
                bitmap[first_offset] &= first_mask
                bitmap[last_offset] &= last_mask
            value = 0xff if allocate else 0x00
            for index in range(first_offset + 1, last_offset):
                bitmap[index] = value

    def _getAllocatedIterator(self, offset):
        bitmap = self.__bitmap
        bitmap_entry, shift = divmod(offset, 8)
        bitmap_bit = 1 << shift
        while True:
            yield bitmap[bitmap_entry] & bitmap_bit
            bitmap_bit <<= 1
            if bitmap_bit > 0x80:
                bitmap_bit = 1
                bitmap_entry += 1

    def _checkSpaceInFile(self, offset, length):
        if offset + length > len(self.__data):
            raise NoSpaceInFile

    def readBinary(self, offset, length):
        if length == 0:
            length = len(self.__data)
        if offset >= len(self.__data):
            raise WrongParametersP1P2('EOF')
        result = bytearray(length)
        for index, (value, is_allocated) in enumerate(
            zip(
                memoryview(self.__data)[offset:offset + length],
                self._getAllocatedIterator(offset),
            ),
        ):
            result[index] = value if is_allocated else 0x00
        return bytes(result)

    def writeBinary(self, offset, data, mode):
        length = len(data)
        self._checkSpaceInFile(offset, length)
        self._p_changed = True
        if mode is WRITE_MODE_ONCE:
            allocated_iterator = self._getAllocatedIterator(offset)
            for _ in range(length):
                if next(allocated_iterator):
                    raise NoSpaceInFile
            self.__data[offset:offset + length] = data
        else:
            operation = WRITE_MODE_DICT[mode]
            my_data = self.__data
            for value, is_allocated in zip(
                data,
                self._getAllocatedIterator(offset),
            ):
                new_value = operation(
                    current=my_data[offset],
                    is_allocated=is_allocated,
                    new=value,
                )
                my_data[offset] = new_value
                offset += 1
        self._updateBitmapRange(
            allocate=True,
            offset=offset,
            length=length,
        )

    def updateBinary(self, offset, data):
        length = len(data)
        self._checkSpaceInFile(offset, length)
        self._p_changed = True
        self.__data[offset:offset + length] = data
        self._updateBitmapRange(
            allocate=True,
            offset=offset,
            length=length,
        )

    def searchBinary(self, offset, data):
        self._checkSpaceInFile(offset, 0)
        # XXX: not checking allocation mask, so searching for \x00 will match
        # on first unallocated byte - consistently with what readBinary would
        # return. search and read being both protected by READ permission,
        # this should be fine.
        if data:
            return self.__data.find(data, offset)
        # Return first index in an erased state
        # IOW, first zero in bitmap
        for index, value in enumerate(self.__bitmap):
            if value != 0xff:
                bit_index = 0
                while value & 1:
                    value >>= 1
                    bit_index += 1
                return index * 8 + bit_index
        return -1

    def eraseBinary(self, offset, length):
        self._p_changed = True
        self.updateBinary(offset=offset, data=b'\x00' * length)
        self._updateBitmapRange(
            allocate=False,
            offset=offset,
            length=length,
        )

    def appendBinary(self, data):
        my_data = self.__data
        offset = len(my_data)
        length = len(data)
        self._p_changed = True
        my_data.extend(data)
        bitmap_length, remainder = divmod(len(my_data), 8)
        if remainder:
            bitmap_length += 1
        bitmap_increase = bitmap_length - len(self.__bitmap)
        if bitmap_increase:
            self.__bitmap.extend((0, ) * bitmap_increase)
        self._updateBitmapRange(
            allocate=True,
            offset=offset,
            length=length,
        )

_RECORD_STRUCTURE_DICT = {
    # Cyclic with variable record size is not supported, so (*, True, False) is absent.
    (False, True , True ): FileDescriptor.STRUCTURE_EF_LINEAR_VARIABLE_SIZE,
    (False, False, True ): FileDescriptor.STRUCTURE_EF_LINEAR_FIXED_SIZE,
    (False, False, False): FileDescriptor.STRUCTURE_EF_CYCLIC_FIXED_SIZE,
    (True , True , True ): FileDescriptor.STRUCTURE_EF_LINEAR_VARIABLE_SIZE_COMPOSITE,
    (True , False, True ): FileDescriptor.STRUCTURE_EF_LINEAR_FIXED_SIZE_COMPOSITE,
    (True , False, False): FileDescriptor.STRUCTURE_EF_CYCLIC_FIXED_SIZE_COMPOSITE,
}
RECORD_RANGE_SINGLE = object()
RECORD_RANGE_FROM = object()
RECORD_RANGE_TO = object()
RECORD_RANGE_FIRST = object()
RECORD_RANGE_LAST = object()
RECORD_RANGE_NEXT = object()
RECORD_RANGE_PREVIOUS = object()

class RecordElementaryFile(ElementaryFile):
    __cyclic_position = None

    def __init__(
        self,
        record_length=None,
        record_count=None,
        tlv=False,
        **kw
    ):
        """
        record_length (int, None)
            If None, records are of variable length.
            Otherwise, it is the size of each record.
        record_count (int, None)
            If None, record list has a beginning and an end.
            Otherwise, record list loops.
        tlv (bool)
            If true, records contain simpleTLV-encoded values.
            Otherwise, records contain unstructured data as far as the card
            is concerned.
        """
        self.__record_length = record_length
        self.__cyclic = record_count is not None
        self.__tlv = tlv = bool(tlv)
        super().__init__(
            structure=_RECORD_STRUCTURE_DICT[
                (tlv, record_length is None, record_count is None)
            ],
            record_length=record_length,
            record_count=record_count,
            **kw
        )
        self.__blank()

    def blank(self):
        super().blank()
        self.__blank()

    def __blank(self):
        self.__cyclic_position = 0
        self.__record_list = persistent.list.PersistentList(
            [None] * self.__cyclic,
        )

    def getFileSize(self):
        return sum(
            0 if x is None else len(x)
            for x in self.__record_list
        )

    def _getTagFileDescriptor(self):
        base, = super()._getTagFileDescriptor()
        base = bytearray(base)
        length = len(self.__record_list)
        base[-2] = length >> 8
        base[-1] = length & 0xff
        return bytes(base)

    def _getRecordList(self):
        record_list = self.__record_list
        if self.__cyclic:
            position = self.__cyclic_position
            return record_list[position:] + record_list[:position]
        return record_list

    def readRecord(self, reference, record_range, reference_is_index):
        record_list = self._getRecordList()
        if reference_is_index:
            # XXX: raise on cyclic ?
            if record_range is RECORD_RANGE_SINGLE:
                return record_list[reference]
            elif record_range is RECORD_RANGE_FROM:
                return record_list[reference:]
            elif record_range is RECORD_RANGE_TO:
                return record_list[:reference]
            raise WrongParametersP1P2('unknown range')
        else:
            # XXX: dead code (nothing calls with reference_is_index = False)
            if not self.__tlv:
                raise InstructionIncompatibleWithFile
            candidate_list = [
                x
                for x in record_list
                if reference == CodecSimple.decodeTag(x)[0]
            ]
            if self.__cyclic:
                if record_range is RECORD_RANGE_FIRST:
                    return candidate_list[0]
                elif record_range is RECORD_RANGE_LAST:
                    return candidate_list[-1]
                raise InstructionIncompatibleWithFile
            else:
                if record_range is RECORD_RANGE_NEXT:
                    return candidate_list[0]
                elif record_range is RECORD_RANGE_PREVIOUS:
                    return candidate_list[-1]
                raise InstructionIncompatibleWithFile

    def writeRecord(self, index, record_range, data, mode):
        # TODO: handle record_range
        record_list = self.__record_list
        length = len(record_list)
        if index > length:
            raise NoSpaceInFile
        if self.__record_length is not None and len(data) > self.__record_length:
            raise WrongLength
        if self.__tlv:
            # Raises if value is truncated
            _, _, trailer = CodecSimple.decode(data, schema=AllSchema)
            if trailer:
                raise WrongLength
        if self.__cyclic:
            index = (index + self.__cyclic_position) % length
        if mode is WRITE_MODE_ONCE:
            if record_list[index] is not None:
                raise NoSpaceInFile
            record_list[index] = bytearray(data)
        else:
            # XXX: has good chances of producing garbage on tlv items...
            existing_record = record_list[index]
            if existing_record is None:
                new_record = bytearray(data)
            else:
                new_record = bytearray(max(len(data), len(existing_record)))
                operation = WRITE_MODE_DICT[mode]
                for offset, (current, new) in enumerate(
                    itertools.zip_longest(existing_record, data),
                ):
                    if current is None:
                        new_record[offset] = new
                    elif new is None:
                        new_record[offset] = current
                    else:
                        new_record[offset] = operation(
                            current=current,
                            is_allocated=True,
                            new=new,
                        )
            record_list[index] = new_record
        if self.__cyclic:
            self.__cyclic_position = index

    def updateRecord(self, index, data, mode, offset=0):
        record_list = self.__record_list
        length = len(record_list)
        if index > length:
            raise NoSpaceInFile
        if self.__record_length is not None and len(data) > self.__record_length:
            raise WrongLength
        if self.__cyclic:
            index = (index + self.__cyclic_position) % length
        existing = record_list[index]
        if existing is not None and len(existing) != len(data):
            raise WrongLength
        if self.__tlv:
            # Raises if value is truncated
            _, _, trailer = CodecSimple.decode(data, schema=AllSchema)
            if trailer:
                raise WrongLength
        if mode is RECORD_RANGE_FIRST:
            raise NotImplementedError # What does this mean without a type parameter ?
            #record_list[index] = bytearray(data)
        elif mode is RECORD_RANGE_LAST:
            raise NotImplementedError # What does this mean without a type parameter ?
            #record_list[index] = bytearray(data)
        elif mode is RECORD_RANGE_NEXT:
            raise NotImplementedError # What does this mean without a type parameter ?
            #record_list[index] = bytearray(data)
        elif mode is RECORD_RANGE_PREVIOUS:
            if self.__cyclic:
                raise NotImplementedError # "same as append"
            raise NotImplementedError # What does this mean without a type parameter ?
            #record_list[index] = bytearray(data)
        elif mode is WRITE_MODE_REPLACE:
            record_list[index][offset:offset + len(data)] = data
        else:
            # XXX: has good chances of producing garbage on tlv items...
            existing_record = record_list[index]
            if existing_record is None:
                new_record = bytearray(data)
            else:
                existing_record = memoryview(existing_record)
                new_record = bytearray(max(len(data), len(existing_record)))
                if offset:
                    new_record[:offset] = existing_record[:offset]
                operation = WRITE_MODE_DICT[mode]
                for new_record_offset, (current, new) in enumerate(
                    itertools.zip_longest(
                        existing_record[offset:],
                        data,
                    ),
                    offset,
                ):
                    if current is None:
                        new_record[new_record_offset] = new
                    elif new is None:
                        new_record[new_record_offset] = current
                    else:
                        new_record[new_record_offset] = operation(
                            current=current,
                            is_allocated=True,
                            new=new,
                        )
            record_list[index] = new_record
        if self.__cyclic:
            self.__cyclic_position = index

    def appendRecord(self, data):
        if self.__record_length is not None and len(data) > self.__record_length:
            raise WrongLength
        data = bytearray(data)
        if self.__cyclic:
            index = (1 + self.__cyclic_position) % len(self.__record_list)
            self.__record_list[index] = data
            self.__cyclic_position = index
        else:
            if len(self.__record_list) == 0xffff:
                raise NoSpaceInFile
            self.__record_list.append(data)

    def searchRecord(self):
        raise NotImplementedError

# TODO, then enable DATA_CODING_BYTE_TLV_STRUCTURED_EF in MasterFile
#class TLVElementaryFile(ElementaryFile):
#    def __init__(self, bertlv=True, **kw):
#        super().__init__(
#            file_type=bytearray((
#                FILE_DESCRIPTOR_ELEMENTARY_FILE_TLV_STRUCTURE_BER_TLV
#                if bertlv else
#                FILE_DESCRIPTOR_ELEMENTARY_FILE_TLV_STRUCTURE_SIMPLE_TLV,
#            )),
#            **kw
#        )
#
#    # data objects

class DedicatedFile(BaseFile):
    def __init__(
        self,
        name,
        **kw
    ):
        super().__init__(
            file_type=FileDescriptor.FILE_TYPE_DEDICATED,
            **kw
        )
        self.__blank(name)

    def blank(self):
        name = self.name
        super().blank()
        self.__blank(name)

    def __blank(self, name):
        self.putData(FileName, name, encode=True)
        self.__child_by_identifier_dict = persistent.mapping.PersistentMapping()

    @property
    def _dynamicChildrenDict(self):
        # XXX: only works for by-identifier access...
        return {}

    def setStandardCompactSecurity(
        self,
        delete_child=SECURITY_CONDITION_DENY,
        create_elementary_file=SECURITY_CONDITION_DENY,
        create_dedicated_file=SECURITY_CONDITION_DENY,
        deactivate=SECURITY_CONDITION_DENY,
        activate=SECURITY_CONDITION_DENY,
        terminate=SECURITY_CONDITION_DENY,
        delete=SECURITY_CONDITION_DENY,
    ):
        self.putData(
            FileSecurityCompactFormat,
            {
                FileSecurityCompactFormat.DELETE_CHILD:           delete_child,
                FileSecurityCompactFormat.CREATE_ELEMENTARY_FILE: create_elementary_file,
                FileSecurityCompactFormat.CREATE_DEDICATED_FILE:  create_dedicated_file,
                FileSecurityCompactFormat.DEACTIVATE:             deactivate,
                FileSecurityCompactFormat.ACTIVATE:               activate,
                FileSecurityCompactFormat.TERMINATE:              terminate,
                FileSecurityCompactFormat.DELETE_SELF:            delete,
            },
            index=0,
            encode=True,
        )

    def create(self, subfile):
        # All files have an identifier
        identifier = subfile.identifier
        assert isinstance(identifier, bytes) and len(identifier) == 2, (repr(subfile), repr(identifier))
        if identifier in self._dynamicChildrenDict:
            raise FileExists
        other_subfile = self.__child_by_identifier_dict.setdefault(
            identifier,
            subfile,
        )
        if other_subfile is not subfile:
            raise FileExists

    @property
    def name(self):
        return self.getData(FileName, decode=True)

    def getChildByIdentifier(self, identifier, default=None):
        getter_id = self._dynamicChildrenDict.get(identifier)
        if getter_id is not None:
            return getattr(self, getter_id)()
        return self.__child_by_identifier_dict.get(identifier, default)

    def _recurse(self, method_id, kw=()):
        kw = dict(kw)
        for child in self.__child_by_identifier_dict.values():
            getattr(child, method_id)(**kw)
        getattr(super(), method_id)(**kw)

    def terminate(self, channel):
        self._recurse('terminate', kw={'channel': channel})

    def activate(self, channel):
        self._recurse('activate', kw={'channel': channel})

    def deactivate(self, channel):
        self._recurse('deactivate', kw={'channel': channel})

class MasterFile(DedicatedFile):
    def __init__(self, channel_count, **kw):
        super().__init__(
            identifier=MASTER_FILE_IDENTIFIER,
            shared=True,
            data_coding_byte=getDataCodingByte(
                supports_ef_with_tlv_content=False,
                write_function_behaviour=WRITE_FUNCTION_ONE_TIME,
                supports_ff_tag=True,
                size_unit=2, # 1 byte unit
            ),
            **kw
        )
        self.__channel_count = channel_count

    def getAnswerToReset(self):
        historical_bytes = self.getData(HistoricalData, decode=False)
        assert len(historical_bytes) <= 15, repr(historical_bytes)
        atr_data = bytearray(
            # ATR (Answer To Reset) string
            # Most of this is totally irrelevant to virtual cards & readers
            # but will be expected (especially the historical bytes) by the
            # host application.
            # TS = 0x3b: Direct convention
            # T0 = 0xdN: TA1, TC1 and TD1 follow, N historical bytes
            # TA1 = 0x11: FI=1 (5MHz max), DI=1 (1 bit per cycle)
            # TC1 = 0xff: N=255 (character guard interval, irrelevant to
            #                    virtual card & reader)
            # TD1 = 0x81: TD2 follows, first offered protocol is T=1
            #             (block protocol)
            # TD2 = 0xb1: TA3, TB3 and TD3 follow, T=1 (block protocol)
            # TA3 = 0xfe: IFSC = 254 bytes (card can receive information fields
            #                               up to 254 bytes-long)
            # TB3 = 0x55: BWI = 5, CWI = 5   (BWT timeout 3.2 sec)
            # No TC3: LRC error detection (default)
            # TD3 = 0x1f: TA4 follows, T=15 (global interface bytes)
            # TA4 = 0x03: Clock stop not supported, 5V and 3.3V supported
            b'\x3b' + (
                0xd0 | len(historical_bytes)
            ).to_bytes(1, 'big') + b'\x11\xff\x81\xb1\xfe\x55\x1f\x03',
        ) + historical_bytes + bytearray(1) # TCK
        assert len(atr_data) <= 32, len(atr_data)
        atr_data[-1] = _xor(atr_data[1:]) # Compute TCK
        return atr_data

    def getHistoricalData(self):
        return bytearray((
            HISTORICAL_BYTES_CATEGORY_STATUS_RAW,
        )) + CodecCompact.encode(
            tag=CardServiceData,
            value={
                'can_select_full_df_name': True,
                'can_select_partial_df_name': True,
                'ef_dir_is_bertlv': False,
                'ef_atr_is_bertlv': False,
                'ef_dir_ef_atr_access_mode': CardServiceData.EF_DIR_EF_ATR_ACCESS_MODE_READ_BINARY,
                'has_master_file': True,
            },
        ) + CodecCompact.encode(
            tag=CardCapabilities,
            value={
                'can_select_full_df_name': True,
                'can_select_partial_df_name': True,
                'can_select_path': True,
                'can_select_file_identifier': True,
                'has_implicit_df_selection': True,
                'supports_short_ef_identifier': False,
                'supports_record_number': True,
                'supports_record_identifier': True,
                'data_coding_byte': self.getData(
                    FileDescriptor,
                    decode=True,
                )['data_coding_byte'],
                'supports_command_chaining': True,
                'supports_extended_lenghts': True,
                'extended_lengths_ef_atr': False, # XXX: True ?
                'channel_assignment_by_card': True,
                'channel_assignment_by_host': True,
                'channel_count': self.__channel_count,
            },
        ) + bytearray((self.lifecycle, )) + SUCCESS

    def _getAnswerToReset(self):
        return (bytes(self.getAnswerToReset()), )

    def _getHistoricalData(self):
        return (bytes(self.getHistoricalData()), )

    @property
    def _dynamicGetDataObjectDict(self):
        result = super()._dynamicGetDataObjectDict
        result[AnswerToReset] = '_getAnswerToReset'
        result[HistoricalData] = '_getHistoricalData'
        return result

    def _getEF_ATR(self):
        atr_data = self.getAnswerToReset()
        # EF.ATR
        ef_atr = TransparentElementaryFile(
            identifier=EF_ATR_IDENTIFIER,
            internal=False,
            length=len(atr_data),
        )
        ef_atr.updateBinary(offset=0, data=atr_data)
        ef_atr.putData(CardLifecycle, self.lifecycle, encode=True)
        return ef_atr

    @property
    def _dynamicChildrenDict(self):
        result = super()._dynamicChildrenDict
        result[EF_ATR_IDENTIFIER] = '_getEF_ATR'
        return result

    @property
    def channel_count(self):
        return self.__channel_count

class ApplicationFile(DedicatedFile):
    # TODO: allow intercepting (some) APDUs
    def __init__(self, **kw):
        super().__init__(**kw)
        self.__blank()

    def blank(self):
        super().blank()
        self.__blank()

    def __blank(self):
        self.putData(
            ApplicationIdentifier,
            self.getData(FileName, decode=False),
            encode=False,
        )

ATR_TS_DIRECT_CONVENTION = 0x3b
ATR_TS_INVERSE_CONVENTION = 0x3f

class SecurityStatus(Antipersistent):
    def __init__(self):
        super().__init__()
        self._private = {}

    def getPrivate(self):
        return self._private

class Channel(Antipersistent):
    _queue = None
    _elementary_security = None
    dedicated_file_path = None
    elementary_file_identifier = None
    _data_object_index_dict = None
    _user_authentication_level = 0

    def __init__(self, card, number):
        super().__init__()
        self._card = card
        self.number = number
        self.clearVolatile()

    def clearVolatile(self):
        self.dedicated_file_path = ()
        self._dedicated_security_chain = []
        self.elementary_file_identifier = None
        self._elementary_security = None
        self._queue = None
        # XXX: per element ? assume global to channel and reset on select
        self._data_object_index_dict = {}
        self._user_authentication_level = 0

    def getDataObjectIndex(self, tag):
        return self._data_object_index_dict.get(tag, 0)

    def setDataObjectIndex(self, tag, index):
        self._data_object_index_dict[tag] = index

    def getPrivate(self):
        if self._elementary_security is None:
            return self._dedicated_security_chain[-1].getPrivate()
        return self._elementary_security.getPrivate()

    def select(self, dedicated_file_path, elementary_file_identifier=None):
        identical = True
        # Preserve common path security chain, fill the rest with new security
        # status instances.
        dedicated_security_chain = self._dedicated_security_chain
        for index, (previous_chunk, new_chunk) in enumerate(
            itertools.zip_longest(
                self.dedicated_file_path,
                dedicated_file_path,
            ),
        ):
            if identical:
                if previous_chunk == new_chunk:
                    continue
                else:
                    identical = False
                    del dedicated_security_chain[index:]
            if new_chunk is None:
                break
            dedicated_security_chain.append(SecurityStatus())
        self.dedicated_file_path = tuple(dedicated_file_path)
        self.elementary_file_identifier = elementary_file_identifier
        self._elementary_security = SecurityStatus()
        self._data_object_index_dict = {}

    def getQueuedLen(self):
        return 0 if self._queue is None else len(self._queue)

    def queue(self, data):
        """
        APDU response is larger than requested length, stash the response data
        (which must have a SUCCESS status) for incremental retrieval.
        """
        assert self._queue is None
        if data[-2:] != SUCCESS:
            raise ValueError(data[-2:].hex())
        self._queue = data[:-2]

    def dequeue(self, response_len):
        """
        Incrementally retrieve response_len bytes from stashed response data,
        and append with a status informing on how many bytes are left to read.
        """
        result = self._queue[:response_len]
        remain = self._queue[response_len:]
        if remain:
            self._queue = remain
            return result + successWithMoreResponseBytes(
                min(0xff, len(remain)),
            )
        self._queue = None
        return result + SUCCESS

    def traverse(self, path=None):
        if path is None:
            path = self.dedicated_file_path
            elementary_file_identifier = self.elementary_file_identifier
            if elementary_file_identifier is not None:
                path = path + (elementary_file_identifier, )
        else:
            path = tuple(path)
            if path == (CURRENT_ELEMENTARY_FILE, ):
                elementary_file_identifier = self.elementary_file_identifier
                if elementary_file_identifier is None:
                    raise NoCurrentElementaryFile
                path = self.dedicated_file_path + (elementary_file_identifier, )
            elif path[0] == CURRENT_DEDICATED_FILE:
                path = self.dedicated_file_path + path[1:]
        return self._card.traverse(path)

    def setUserAuthentication(self, level):
        if level > 0xf:
            raise ValueError
        self._user_authentication_level |= 1 << level

    def clearUserAuthentication(self, level):
        if level > 0xf:
            raise ValueError
        self._user_authentication_level &= ~(1 << level)

    def isUserAuthenticated(self, level):
        if level > 0xf:
            raise ValueError
        return bool(self._user_authentication_level & (1 << level))

    def checkUserAuthentication(self, level):
        if not self.isUserAuthenticated(level=level):
            raise SecurityNotSatisfied('not authenticated at level %r' % (level, ))

    def validateChannelSecurity(self, channel_security):
        raise NotImplementedError

    def _isSecurityEnvironmentIdentifierApplicable(self, identifier):
        return False # TODO

    def _validateSecurityCondition(self, tag, security_condition):
        if tag is SecurityConditionDataObjectList.Always:
            assert not security_condition
            return
        elif tag is SecurityConditionDataObjectList.Never:
            assert not security_condition
            raise SecurityNotSatisfied('SecurityConditionDataObjectList.Never')
        elif tag == SecurityConditionDataObjectList.Byte:
            security_environment_id = security_condition & SECURITY_CONDITION_SECURITY_ENVIRONMENT_MASK
            if security_condition == SECURITY_CONDITION_ALLOW:
                return
            elif security_condition == SECURITY_CONDITION_DENY:
                raise SecurityNotSatisfied('SecurityConditionDataObjectList.Byte: SECURITY_CONDITION_DENY')
            elif security_condition & SECURITY_CONDITION_SECURE_MESSAGING:
                raise NotImplementedError # Fold into any/all condition below
            elif security_condition & SECURITY_CONDITION_EXTERNAL_AUTHENTICATION:
                raise NotImplementedError # Fold into any/all condition below
            elif (
                any # We want all conditions == any mismatch raises
                if (
                    security_condition & SECURITY_CONDITION_LOGICAL_MASK ==
                    SECURITY_CONDITION_LOGICAL_AND
                ) else
                all # We want any condition == all-mismatch raises
            )((
            #    # TODO: SECURITY_CONDITION_SECURE_MESSAGING
            #    # TODO: SECURITY_CONDITION_EXTERNAL_AUTHENTICATION
                (
                    security_condition & SECURITY_CONDITION_USER_AUTHENTICATION and
                    # XXX: not sure if this is intended in the standard...
                    not self.isUserAuthenticated(security_environment_id)
                ),
            )):
                raise SecurityNotSatisfied('SecurityConditionDataObjectList.Byte: %02x' % security_condition)
            else: # Should never be reached (SEID set but no condition bit)
                ValueError('SecurityConditionDataObjectList.???: %02x' % security_condition)
        elif tag == SecurityConditionDataObjectList.AuthenticationTemplate:
            raise NotImplementedError
        elif tag == SecurityConditionDataObjectList.ChecksumTemplate:
            raise NotImplementedError
        elif tag == SecurityConditionDataObjectList.SignatureTemplate:
            raise NotImplementedError
        elif tag == SecurityConditionDataObjectList.ConfidentialityTemplate:
            raise NotImplementedError
        elif tag == SecurityConditionDataObjectList.Or:
            validateSecurityCondition = self._validateSecurityCondition
            for inner_tag, inner_value in security_condition:
                try:
                    validateSecurityCondition(
                        tag=inner_tag,
                        security_condition=inner_value,
                    )
                except SecurityNotSatisfied:
                    pass
                else:
                    break
            else:
                raise SecurityNotSatisfied('SecurityConditionDataObjectList.Or')
        elif tag == SecurityConditionDataObjectList.Not:
            (inner_tag, inner_value), = security_condition
            try:
                self._validateSecurityCondition(
                    tag=inner_tag,
                    security_condition=inner_value,
                )
            except SecurityNotSatisfied:
                pass
            else:
                raise SecurityNotSatisfied('SecurityConditionDataObjectList.Not')
        elif tag == SecurityConditionDataObjectList.And:
            validateSecurityCondition = self._validateSecurityCondition
            for inner_tag, inner_value in security_condition:
                validateSecurityCondition(
                    tag=inner_tag,
                    security_condition=inner_value,
                )
        else:
            raise NotImplementedError

    def _validateProprietarySecurity(self, permission, apdu_head, tag, value):
        # TODO: delegate to current dedicated file
        raise NotImplementedError

    def _doesProprietaryStateMachineMatch(self, permission, apdu_head, value):
        # TODO: delegate to current dedicated file
        raise NotImplementedError

    def _validateExpandedFormat(self, permission, apdu_head, expanded_template):
        # TODO: implement
        raise NotImplementedError

    def _iterResolvedExpandedFormatReference(self, expanded_format_reference):
        ef_arr = self.traverse(
            (
                CURRENT_DEDICATED_FILE,
                expanded_format_reference.get(
                    'file_identifier',
                    EF_ARR_IDENTIFIER,
                ),
            ),
        )
        rule_index_list = [
            arr
            for seid, arr in expanded_format_reference.get(
                'security_environment_list',
                (),
            )
            if self._isSecurityEnvironmentIdentifierApplicable(seid)
        ]
        try:
            rule_index_list.append(
                expanded_format_reference['access_rule_record_number'],
            )
        except KeyError:
            pass
        for rule_index in rule_index_list:
            yield FileSecurityExpandedFormatReference.decode(
                ef_arr.readRecord(
                    rule_index,
                    record_range=RECORD_RANGE_SINGLE,
                    reference_is_index=True,
                ),
                codec=CodecBER,
            )

    def _validateCompactFormat(self, permission, compact):
        try:
            security_condition = compact[permission]
        except KeyError:
            raise SecurityNoMatch('No permission record for %r' % (permission, )) from None
        else:
            self._validateSecurityCondition(
                tag=SecurityConditionDataObjectList.Byte,
                security_condition=security_condition,
            )

    def _validate(self, permission, apdu_head, tag, value):
        if tag is FileSecurityCompactFormat:
            self._validateCompactFormat(
                permission=permission,
                compact=value,
            )
        elif tag is FileSecurityTemplateExpandedFormat:
            self._validateExpandedFormat(
                permission=permission,
                apdu_head=apdu_head,
                expanded_template=value,
            )
        elif tag == FileChannelSecurity:
            self.validateChannelSecurity(value)
        elif tag in (
            FileSecurityProprietary,
            FileDataObjectSecurityProprietary,
        ):
            self._validateProprietarySecurity(
                permission=permission,
                apdu_head=apdu_head,
                tag=tag,
                value=value,
            )
        # DO NOT add FileDataObjectSecurityTemplate !
        else:
            raise ValueError

    def validate(self, permission, apdu_head, tag, value):
        if tag is FileSecurityExpandedFormatReference:
            for expanded_value in self._iterResolvedExpandedFormatReference(
                expanded_format_reference=value,
            ):
                self._validate(
                    permission=permission,
                    apdu_head=apdu_head,
                    tag=FileSecurityTemplateExpandedFormat,
                    value=expanded_value,
                )
        else:
            self._validate(
                permission=permission,
                apdu_head=apdu_head,
                tag=tag,
                value=value,
            )

class Card(PersistentWithVolatileSurvivor):
    _v_s_apdu_chaining_head = None
    _v_s_apdu_chaining = None

    def __init__(self,
        name,
        channel_count=19,
        terminate_blanks=True,
    ):
        if not 1 <= channel_count <= 19:
            raise ValueError('channel_count must be at least 1 and at most 19')
        self.__terminate_blanks = terminate_blanks
        super().__init__()
        self.__path_by_name_dict = persistent.mapping.PersistentMapping()
        # Populate file tree.
        self.__root = MasterFile(
            name=name,
            channel_count=channel_count,
        )
        self.__ef_arr = RecordElementaryFile(
            identifier=EF_ARR_IDENTIFIER,
            internal=False,
            tlv=True,
        )
        self.__ef_dir = TransparentElementaryFile(
            identifier=EF_DIR_IDENTIFIER,
            internal=False,
            lifecycle=LifecycleBase.ACTIVATED,
            length=0,
        )
        self.__ef_gdo = TransparentElementaryFile(
            identifier=EF_GDO_IDENTIFIER,
            internal=False,
            lifecycle=LifecycleBase.ACTIVATED,
            length=0,
        )
        self.setupVolatileSurvivors()
        self.__blank()

    def blank(self):
        self.__root.blank()
        self.__ef_arr.blank()
        self.__ef_dir.blank()
        self.__ef_gdo.blank()
        self.__path_by_name_dict.clear()
        self.__blank()

    def __blank(self):
        root = self.__root
        self.__path_by_name_dict[root.name] = (root.identifier, )
        ef_arr = self.__ef_arr
        ef_arr.setStandardCompactSecurity(
            read=SECURITY_CONDITION_ALLOW,
        )
        self.createFile(root, ef_arr)
        ef_dir = self.__ef_dir
        ef_dir.setStandardCompactSecurity(
            read=SECURITY_CONDITION_ALLOW,
        )
        self.createFile(root, ef_dir)
        ef_gdo = self.__ef_gdo
        ef_gdo.appendBinary(
            # XXX: is there any structure to respect ? Assume there is none and
            # put random bytes.
            data=CardSerialNumber.encode(
                value=random.getrandbits(16 * 8).to_bytes(16, 'big'),
                codec=CodecBER,
            ),
        )
        ef_gdo.setStandardCompactSecurity(
            read=SECURITY_CONDITION_ALLOW,
        )
        self.createFile(root, ef_gdo)

    def setupVolatileSurvivors(self):
        self._v_s_channel_list = [
            Channel(self, index)
            for index in range(self.__root.channel_count)
        ]
        self.clearVolatile()

    def clearVolatile(self):
        """
        Clear any volatile state: authentication level, ...
        Note: while these are Persistent-volatile attributes (or attributes of
        Persistent-volatile attributes...), not all Persistent-volatile
        attributes need to be cleared.
        """
        for channel in self._v_s_channel_list:
            channel.clearVolatile()
        self._v_s_channel_list[0].select(
            dedicated_file_path=(MASTER_FILE_IDENTIFIER, ),
        )
        self._clearAPDUChaining()

    def createFile(self, container, value):
        # TODO: check identifier unicity amongst parent, children and siblings
        # of any file.
        is_dedicated_file = isinstance(value, DedicatedFile)
        if is_dedicated_file:
            name = value.name
            if name in self.__path_by_name_dict:
                raise DedicatedFileNameExists
        container.create(value)
        if is_dedicated_file:
            self.__path_by_name_dict[name] = (
                self.__path_by_name_dict[container.name] + (
                    value.identifier,
                )
            )
        if isinstance(value, ApplicationFile):
            dir_record = value.getData(ApplicationTemplate, decode=True)
            if dir_record is None:
                dir_record = []
                for tag in (
                    ApplicationIdentifier,
                    ApplicationLabel,
                    FileReference,
                    CommandAPDU,
                    DiscretionaryData,
                    DiscretionaryTemplate,
                    URL,
                ):
                    tag_value = value.getData(tag, index=0, decode=True)
                    if tag_value is not None:
                        dir_record.append((tag, tag_value))
                # At least ApplicationIdentifier must be present
                assert dir_record
            self.__ef_dir.appendBinary(
                ApplicationTemplate.encode(
                    dir_record,
                    codec=CodecSimple,
                ),
            )

    def _clearAPDUChaining(self):
        self._v_s_apdu_chaining_head = None
        self._v_s_apdu_chaining = []

    def traverse(self, path):
        """
        path (list of ints)
            Identifiers to traverse to, from the Master File.
        Returns either a file, or None if any element could not be found.
        """
        current = self.__root
        if path[0] == MASTER_FILE_IDENTIFIER:
            path = path[1:]
        for element in path:
            current = current.getChildByIdentifier(element)
            if current is None:
                return None
        return ProxyFile(path_list=path, real_file=current)

    def getATR(self):
        """
        Return the Answer-To-Reset data.
        """
        atr = self.traverse((MASTER_FILE_IDENTIFIER, )).getAnswerToReset()
        logger.debug('Card.getATR: %s', atr.hex())
        return atr

    def handleSelect(
        self,
        apdu_head,
        channel,
        command_data,
        response_len,
    ):
        p1 = apdu_head.parameter1
        p2 = apdu_head.parameter2
        if p2 & 0xf0:
            raise WrongParametersP1P2('unhandled p2: %02x' % (p2, ))
        # Convert all to absolute paths.
        if p1 == INSTRUCTION_SELECT_P1_ANY:
            # Select EF or DF by identifier from current file
            if command_data:
                if len(command_data) != 2:
                    # All identifiers are 2-bytes-long.
                    raise WrongLength('2 expected')
                command_data = command_data.tobytes()
                # The identifier must be unique amongst parent, children
                # and siblings. Assume this is true.
                current_dedicated_file_path = channel.dedicated_file_path
                if channel.traverse(
                    current_dedicated_file_path,
                ).getChildByIdentifier(command_data) is not None:
                    # It is a child file
                    selected_file_path = current_dedicated_file_path + (
                        command_data,
                    )
                elif current_dedicated_file_path[-2:-1] == (command_data, ):
                    # It is parent file
                    selected_file_path = current_dedicated_file_path[:-1]
                else:
                    # So sibling file it will be
                    selected_file_path = current_dedicated_file_path[:-1] + (
                        command_data,
                    )
            else:
                # ... or by nothing, select master file.
                selected_file_path = (MASTER_FILE_IDENTIFIER, )
            expected_type = BaseFile
        elif p1 in (
            INSTRUCTION_SELECT_P1_CHILD_DEDICATED_FILE,
            INSTRUCTION_SELECT_P1_CHILD_ELEMENTARY_FILE,
        ):
            # Select one child DF *or* EF.
            if len(command_data) != 2:
                raise WrongLength('2 expected')
            command_data = command_data.tobytes()
            selected_file_path = channel.dedicated_file_path + (command_data, )
            expected_type = (
                ElementaryFile
                if p1 == INSTRUCTION_SELECT_P1_CHILD_ELEMENTARY_FILE else
                DedicatedFile
            )
        elif p1 == INSTRUCTION_SELECT_P1_PARENT:
            # Select parent, or do nothing at root.
            if command_data:
                raise WrongLength('0 expected')
            selected_file_path = list(channel.dedicated_file_path)
            if len(selected_file_path) > 1:
                selected_file_path.pop()
            expected_type = DedicatedFile
        elif p1 == INSTRUCTION_SELECT_P1_BY_NAME:
            # Select by name (including application identifiers), possibly a
            # prefix of any length.
            # XXX: This code accepts zero-length prefixes, which allows
            # iterating over all dedicated files.
            command_data = command_data.tobytes()
            dedicated_file_list = [
                y
                for x, y in sorted(self.__path_by_name_dict.items())
                if x.startswith(command_data)
            ]
            whence = p2 & INSTRUCTION_SELECT_P2_WHENCE_MASK
            try:
                # Absolute position, easy
                if whence == INSTRUCTION_SELECT_P2_WHENCE_FIRST:
                    selected_file_path = dedicated_file_list[0]
                elif whence == INSTRUCTION_SELECT_P2_WHENCE_LAST:
                    selected_file_path = dedicated_file_list[-1]
                else:
                    # Relative position, locate where we are...
                    dedicated_file_index = dedicated_file_list.index(
                        channel.dedicated_file_path,
                    )
                    # ...and move
                    if whence == INSTRUCTION_SELECT_P2_WHENCE_NEXT:
                        dedicated_file_index += 1
                    else: # whence == INSTRUCTION_SELECT_P2_WHENCE_PREVIOUS
                        dedicated_file_index -= 1
                        if dedicated_file_index < 0:
                            raise IndexError
                    selected_file_path = dedicated_file_list[dedicated_file_index]
            except IndexError:
                raise FileNotFound from None
            expected_type = DedicatedFile
        elif p1 in (
            INSTRUCTION_SELECT_P1_BY_ABSOLUTE_PATH,
            INSTRUCTION_SELECT_P1_BY_RELATIVE_PATH,
        ):
            # Select by path, which is a string of byte pairs (no distinguished
            # path here).
            item_count, remainder = divmod(len(command_data), 2)
            if remainder:
                raise WrongLength('even expected')
            selected_file_path = []
            offset = 0
            for _ in range(item_count):
                previous_offset = offset
                offset += 2
                selected_file_path.append(command_data[previous_offset:offset].tobytes())
            if p1 == INSTRUCTION_SELECT_P1_BY_RELATIVE_PATH:
                selected_file_path.insert(0, CURRENT_DEDICATED_FILE)
            expected_type = BaseFile
        else:
            raise WrongParametersP1P2('unhandled p1: %02x' % (p1, ))
        # TODO: check traversal permission
        selected_file = channel.traverse(selected_file_path)
        if selected_file is None or not selected_file.isinstance(
            expected_type,
        ):
            raise FileNotFound
        selected_file_lifecycle = selected_file.lifecycle
        if (
            selected_file_lifecycle & LifecycleBase.ACTIVATED_MASK
        ) == LifecycleBase.DEACTIVATED:
            result = WARNING_FILE_DEACTIVATED
        elif (
            selected_file_lifecycle & LifecycleBase.TERMINATED_MASK
        ) == LifecycleBase.TERMINATED:
            result = WARNING_FILE_TERMINATED
        else:
            result = SUCCESS
        if selected_file.isinstance(ElementaryFile):
            dedicated_file_path = selected_file_path[:-1]
            elementary_file_identifier = selected_file_path[-1]
        else:
            dedicated_file_path = selected_file_path
            elementary_file_identifier = None
        channel.select(dedicated_file_path, elementary_file_identifier)
        return_data = p2 & INSTRUCTION_SELECT_P2_RETURN_MASK
        if response_len:
            if return_data == INSTRUCTION_SELECT_P2_RETURN_PROPRIETARY:
                raise NotImplementedError # proprietary
            else:
                to_wrap_tag_list = []
                if return_data in (
                    INSTRUCTION_SELECT_P2_RETURN_FILE_CONTROL_INFORMATION,
                    INSTRUCTION_SELECT_P2_RETURN_FILE_CONTROL_PARAMETER
                ):
                    to_wrap_tag_list.append(FileControlParameterTemplate)
                if return_data in (
                    INSTRUCTION_SELECT_P2_RETURN_FILE_CONTROL_INFORMATION,
                    INSTRUCTION_SELECT_P2_RETURN_FILE_MANAGEMENT_DATA,
                ):
                    to_wrap_tag_list.append(FileManagementTemplate)
                validate = selected_file.validateDataObjectAccess
                getData = selected_file.getData
                wrapped_list = []
                for wrapper_tag in to_wrap_tag_list:
                    entry_list = []
                    for tag in next(wrapper_tag.iterItemSchema()).values():
                        try:
                            validate(
                                channel=channel,
                                tag_set=set((tag, )),
                                permission=FileSecurityCompactFormat.GET,
                                apdu_head=apdu_head,
                            )
                        except SecurityNotSatisfied:
                            continue
                        value = getData(tag=tag)
                        if value is None:
                            continue
                        entry_list.append((tag, value))
                    if entry_list:
                        wrapped_list.append((
                            wrapper_tag,
                            entry_list,
                        ))
                result = CodecBER.encode(
                    tag=FileControlParametersAndManagementData,
                    value=wrapped_list,
                ) + result
        return result

    def handleManageChannel(
        self,
        apdu_head,
        channel,
        command_data,
        response_len,
    ):
        if command_data:
            raise WrongLength('0 expected')
        p2 = apdu_head.parameter2
        action = (
            apdu_head.parameter1 & INSTRUCTION_MANAGE_CHANNEL_P1_ACTION_MASK
        )
        if action == INSTRUCTION_MANAGE_CHANNEL_P1_ACTION_CLOSE:
            if p2 == 0:
                p2 = channel.number
                if p2 == 0:
                    raise WrongParametersP1P2('cannot close channel 00')
            elif channel.number not in (0, p2):
                raise WrongParametersP1P2(
                    'cannot close channel %02x' % (channel.number, ),
                )
            channel_to_close = self._v_s_channel_list[p2]
            if channel_to_close.dedicated_file_path is None:
                raise WrongParametersP1P2(
                    'channel %02x already closed' % (p2, ),
                )
            channel_to_close.clearVolatile()
            result = b''
        elif action == INSTRUCTION_MANAGE_CHANNEL_P1_ACTION_OPEN:
            if p2:
                try:
                    channel_to_open = self._v_s_channel_list[p2]
                except IndexError as exc:
                    raise WrongParametersP1P2(exc) from None
                if channel_to_open.dedicated_file_path is not None:
                    raise WrongParametersP1P2(
                        'channel %02x already opened' % (p2, ),
                    )
                result = SUCCESS
            else:
                # pylint: disable=redefined-argument-from-local
                for p2, channel_to_open in enumerate(self._v_s_channel_list):
                    if channel_to_open.dedicated_file_path is None:
                        break
                else:
                    raise WrongParametersP1P2('no channel available')
                # pylint: enable=redefined-argument-from-local
                result = bytearray((p2, ))[:response_len] + SUCCESS
            if channel.number:
                channel_to_open.select(channel.dedicated_file_path)
            else:
                channel_to_open.select(MASTER_FILE_IDENTIFIER)
        else:
            raise WrongParametersP1P2('unhandled action %02x' % (action, ))
        return result

    def _getMethodAndTaggedValueList(
        self,
        channel,
        apdu_head,
        is_bertlv,
        command_data,
        method_id,
        permission,
        extra_parameter_type=None,
    ):
        p1 = apdu_head.parameter1
        p2 = apdu_head.parameter2
        command_data_list = []
        if is_bertlv:
            schema = {
                OffsetData.asTagTuple(): OffsetData,
            }
            if extra_parameter_type is not None:
                schema[extra_parameter_type.asTagTuple()] = extra_parameter_type
            file_path = (struct.pack('BB', p1, p2), )
            # XXX: no short identifier support, but (maybe) no way to tell
            # what p1-p2 is (can a file identifier start with 11 zero bits ?)
            try:
                command_data_list = list(CodecBER.iterDecode(
                    value=command_data,
                    schema=schema,
                ))
            except ValueError:
                raise WrongParameterInCommandData from None
        elif p1 & 0x80:
            # XXX: No short identifier support
            raise ParameterFunctionNotSupported(
                'short identifiers are not supported',
            )
        else:
            file_path = None
            command_data_list.append((OffsetData, (p1 << 8) | p2))
            if command_data and extra_parameter_type is not None:
                command_data_list.append((
                    extra_parameter_type,
                    command_data,
                ))
        file_object = channel.traverse(file_path)
        if file_object is None:
            raise FileNotFound
        file_object.validate(
            channel=channel,
            permission=permission,
            apdu_head=apdu_head,
        )
        try:
            method = getattr(file_object, method_id)
        except AttributeError:
            raise InstructionIncompatibleWithFile from None
        return file_object, method, command_data_list

    def handleReadBinary(
        self,
        channel,
        apdu_head,
        is_bertlv,
        command_data,
        response_len,
    ):
        if not is_bertlv and command_data:
            raise WrongParameterInCommandData
        _, method, command_data_list = self._getMethodAndTaggedValueList(
            channel=channel,
            apdu_head=apdu_head,
            is_bertlv=is_bertlv,
            command_data=command_data,
            method_id='readBinary',
            permission=FileSecurityCompactFormat.READ,
        )
        try:
            offset, = (
                value
                for tag, value in command_data_list
                if tag == OffsetData
            )
        except ValueError:
            raise WrongParameterInCommandData from None
        result = method(offset, response_len)
        if is_bertlv:
            result = DiscretionaryData.encode(value=result, codec=CodecBER)
        return result + (
            SUCCESS
            if response_len <= len(result) else
            WARNING_EOF # response_len > len(result)
        )

    def handleWriteBinary(
        self,
        channel,
        apdu_head,
        is_bertlv,
        command_data,
        response_len,
    ):
        _ = response_len # Silence pylint.
        file_object, method, command_data_list = self._getMethodAndTaggedValueList(
            channel=channel,
            apdu_head=apdu_head,
            is_bertlv=is_bertlv,
            command_data=command_data,
            method_id='writeBinary',
            permission=FileSecurityCompactFormat.EXTEND,
            extra_parameter_type=DiscretionaryData,
        )
        try:
            # pylint: disable=unbalanced-tuple-unpacking
            (
                (offset_tag, offset),
                (discretionary_tag, data),
            ) = command_data_list
            # pylint: disable=unbalanced-tuple-unpacking
        except ValueError:
            raise WrongParameterInCommandData from None
        if (
            discretionary_tag != DiscretionaryData
        ) or (
            offset_tag != OffsetData
        ):
            raise WrongParameterInCommandData
        for path_item in file_object.iterPath(channel=channel):
            file_descriptor = path_item.getValue(FileDescriptor, decode=True)
            data_coding_byte = file_descriptor['data_coding_byte']
            if data_coding_byte is not None:
                mode = getWriteFunctionFromDataCodingByte(
                    data_coding_byte=data_coding_byte,
                )
                break
        else:
            mode = WRITE_FUNCTION_OR
        method(offset, data, mode)
        return SUCCESS

    def handleUpdateBinary(
        self,
        channel,
        apdu_head,
        is_bertlv,
        command_data,
        response_len,
    ):
        _ = response_len # Silence pylint.
        _, method, command_data_list = self._getMethodAndTaggedValueList(
            channel=channel,
            apdu_head=apdu_head,
            is_bertlv=is_bertlv,
            command_data=command_data,
            method_id='updateBinary',
            permission=FileSecurityCompactFormat.MODIFY,
            extra_parameter_type=DiscretionaryData,
        )
        try:
            # pylint: disable=unbalanced-tuple-unpacking
            (
                (offset_tag, offset),
                (discretionary_tag, data),
            ) = command_data_list
            # pylint: enable=unbalanced-tuple-unpacking
        except ValueError:
            raise WrongParameterInCommandData from None
        if (
            discretionary_tag != DiscretionaryData
        ) or (
            offset_tag != OffsetData
        ):
            raise WrongParameterInCommandData
        method(offset, data)
        return SUCCESS

    def handleSearchBinary(
        self,
        channel,
        apdu_head,
        is_bertlv,
        command_data,
        response_len,
    ):
        _ = response_len # Silence pylint.
        _, method, command_data_list = self._getMethodAndTaggedValueList(
            channel=channel,
            apdu_head=apdu_head,
            is_bertlv=is_bertlv,
            command_data=command_data,
            method_id='searchBinary',
            permission=FileSecurityCompactFormat.READ,
            extra_parameter_type=DiscretionaryData,
        )
        if len(command_data_list) == 1:
            # pylint: disable=unbalanced-tuple-unpacking
            ((offset_tag, offset), ) = command_data_list
            # pylint: enable=unbalanced-tuple-unpacking
            data = None
        else:
            try:
                # pylint: disable=unbalanced-tuple-unpacking
                (
                    (offset_tag, offset),
                    (discretionary_tag, data),
                ) = command_data_list
                # pylint: enable=unbalanced-tuple-unpacking
            except ValueError:
                raise WrongParameterInCommandData from None
            if discretionary_tag != DiscretionaryData:
                raise WrongParameterInCommandData
        if offset_tag != OffsetData:
            raise WrongParameterInCommandData
        result = method(offset=offset, data=data)
        if result == -1:
            return SUCCESS
        return (
            OffsetData.encode(value=result, codec=CodecBER)
            if is_bertlv else
            encodeBEInteger(result)
        ) + SUCCESS

    def handleEraseBinary(
        self,
        channel,
        apdu_head,
        is_bertlv,
        command_data,
        response_len,
    ):
        _ = response_len # Silence pylint.
        file_object, method, command_data_list = self._getMethodAndTaggedValueList(
            channel=channel,
            apdu_head=apdu_head,
            is_bertlv=is_bertlv,
            command_data=command_data,
            method_id='eraseBinary',
            permission=FileSecurityCompactFormat.MODIFY,
        )
        if not is_bertlv and command_data:
            command_data_list.append(
                (OffsetData, OffsetData.decode(command_data, codec=CodecBER)),
            )
        if len(command_data_list) == 1:
            # pylint: disable=unbalanced-tuple-unpacking
            offset, = command_data_list
            # pylint: enable=unbalanced-tuple-unpacking
            length = file_object.getFileSize()
        else:
            try:
                # pylint: disable=unbalanced-tuple-unpacking
                offset, stop_erasing_at = command_data_list
                # pylint: enable=unbalanced-tuple-unpacking
            except ValueError:
                raise WrongParameterInCommandData from None
            length = stop_erasing_at - offset
        method(offset=offset, length=length)
        return SUCCESS

    def _handleGetData(
        self,
        channel,
        apdu_head,
        is_bertlv,
        command_data,
        response_len,
        preReadHook=lambda tag: None,
    ):
        p1 = apdu_head.parameter1
        p2 = apdu_head.parameter2
        p1p2 = (p1 << 8) | p2
        response_list = []
        if is_bertlv:
            command_tag_list = list(CodecBER.iterDecode(
                command_data,
                schema={
                    x.asTagTuple(): x
                    for x in (
                        FileReference,
                        TagList,
                        TagHeaderList,
                        ExtendedHeaderList,
                    )
                },
            ))
            command_tag_dict = dict(command_tag_list)
            if len(command_tag_dict) != len(command_tag_list):
                raise WrongParameterInCommandData('repeated tags')
            current_file = channel.traverse(((
                command_tag_dict.pop(FileReference)
                if p1p2 == 0 else
                struct.pack('BB', p1, p2)
            ), ))
            if not command_tag_dict and current_file.identifier in (
                EF_DIR_IDENTIFIER,
                EF_ATR_IDENTIFIER,
            ):
                return current_file.readBinary(
                    0,
                    current_file.getFileSize(),
                )
            (list_tag, list_value), = command_tag_dict.items()
            tag_length_list = []
            if list_tag == TagList:
                tag_length_list = [(x, None) for x in list_value]
            elif list_tag == TagHeaderList:
                tag_length_list = list_value
            elif list_tag == ExtendedHeaderList:
                # Unreachable (should raise in the first iterDecode)
                raise NotImplementedError
            else:
                raise WrongParameterInCommandData('unhandled tag list')
            current_file.validateDataObjectAccess(
                channel=channel,
                tag_set={x for x, _ in tag_length_list},
                permission=FileSecurityCompactFormat.GET,
                apdu_head=apdu_head,
            )
            getData = current_file.getData
            for tag, length in tag_length_list:
                preReadHook(tag)
                value = getData(
                    tag=tag,
                    index=channel.getDataObjectIndex(tag=tag),
                )
                if value is not None:
                    value = value[:length]
                    response_list.append(CodecBER.encodeTagLength(
                        tag=tag,
                        length=len(value),
                    ) + value)
        else:
            if command_data:
                raise WrongParameterInCommandData('unexpected command data')
            tag = None
            encodeTag = lambda _: b''
            if p1p2 < 0x40 or p1p2 in (0x200, 0x4000, 0xffff):
                raise ParameterFunctionNotSupported('unhandled DO %04x' % (p1p2, ))
            if 0x40 <= p1p2 <= 0xfe:
                tag, _ = CodecBER.decodeTag((p2, ))
                tag = AllSchema[tag]
            elif p1p2 == 0xff:
                encodeTag = CodecBER.encodeTag
                # select all.
            elif 0x100 <= p1p2 <= 0x1ff:
                # The format of this objects is proprietary, but it is up to
                # the file to decide to accept them or not.
                tag = AllSchema[(CLASS_UNIVERSAL, False, p1p2)]
            elif 0x201 <= p1p2 <= 0x2fe:
                tag, _ = CodecSimple.decodeTag((p2, ))
                tag = AllSchema[tag]
            elif p1p2 == 0x2ff:
                encodeTag = CodecSimple.encodeTag
                # select all data objects which can be encoded in simpleTLV.
            elif 0x4001 <= p1p2 <= 0xfffe:
                tag, remainder = CodecBER.decodeTag((p1, p2))
                if remainder:
                    raise WrongParametersP1P2('decoded tag has a trailer: %r' % (remainder, ))
                tag = AllSchema[tag]
            current_file = channel.traverse()
            if tag is None:
                # XXX: preReadHook is not called, but all occurrences are
                # iterated over anyway.
                value_list = current_file.iterData(decode=False)
            else:
                # XXX: wouldn't it make more sense to move this call in the loop below ?
                preReadHook(tag)
                value_list = [(
                    tag,
                    current_file.getData(
                        tag=tag,
                        index=channel.getDataObjectIndex(tag=tag),
                        decode=False,
                    )
                )]
            for tag, value in value_list:
                current_file.validateDataObjectAccess(
                    channel=channel,
                    tag_set=set((tag, )),
                    permission=FileSecurityCompactFormat.GET,
                    apdu_head=apdu_head,
                )
                if value is None:
                    continue
                response_list.append(encodeTag(tag) + value)
        return b''.join(response_list) + SUCCESS

    def handleGetData(
        self,
        channel,
        apdu_head,
        is_bertlv,
        command_data,
        response_len,
    ):
        return self._handleGetData(
            channel=channel,
            apdu_head=apdu_head,
            is_bertlv=is_bertlv,
            command_data=command_data,
            response_len=response_len,
        )

    def handleGetNextData(
        self,
        channel,
        apdu_head,
        is_bertlv,
        command_data,
        response_len,
    ):
        def preReadHook(tag):
            channel.setDataObjectIndex(
                tag=tag,
                index=channel.getDataObjectIndex(tag=tag) + 1,
            )
        return self._handleGetData(
            channel=channel,
            apdu_head=apdu_head,
            is_bertlv=is_bertlv,
            command_data=command_data,
            response_len=response_len,
            preReadHook=preReadHook,
        )

    def handlePutData(
        self,
        channel,
        apdu_head,
        is_bertlv,
        command_data,
        response_len,
    ):
        _ = response_len # Silence pylint.
        p1 = apdu_head.parameter1
        p2 = apdu_head.parameter2
        # XXX: add (non-standard) extension to allow per-data-object control ?
        p1p2 = (p1 << 8) | p2
        if is_bertlv:
            command_tag_list = list(CodecBER.iterDecode(
                command_data,
                schema={
                    x.asTagTuple(): x
                    for x in (
                        FileReference,
                        TagList,
                        TagHeaderList,
                        ExtendedHeaderList,
                    )
                },
            ))
            command_tag_dict = dict(command_tag_list)
            if len(command_tag_dict) != len(command_tag_list):
                raise WrongParameterInCommandData
            current_file = channel.traverse(((
                command_tag_dict.pop(FileReference)
                if p1p2 == 0 else
                struct.pack('BB', p1, p2)
            ), ))
            tag_list = [
                (tag, bytes(value))
                for tag, value in command_tag_dict.items()
            ]
        else:
            if p1p2 < 0x40 or p1p2 in (0xff, 0x200, 0x2ff, 0x4000, 0xffff):
                raise ParameterFunctionNotSupported
            if 0x40 <= p1p2 <= 0xfe:
                tag, _ = CodecBER.decodeTag((p2, ))
                tag = AllSchema[tag]
            elif 0x100 <= p1p2 <= 0x1ff:
                # The format of this objects is proprietary, but it is up to
                # the file to decide to accept them or not.
                tag = AllSchema[(CLASS_UNIVERSAL, False, p1p2)]
            elif 0x201 <= p1p2 <= 0x2fe:
                tag, _ = CodecSimple.decodeTag((p2, ))
                tag = AllSchema[tag]
            elif 0x4001 <= p1p2 <= 0xfffe:
                tag, remainder = CodecBER.decodeTag((p1, p2))
                if remainder:
                    raise WrongParametersP1P2
                tag = AllSchema[tag]
            if tag.asTagTuple() == Lifecycle.asTagTuple():
                raise WrongParametersP1P2
            current_file = channel.traverse()
            tag_list = [(tag, command_data.tobytes())]
        current_file.validateDataObjectAccess(
            channel=channel,
            tag_set={x for x, _ in tag_list},
            permission=FileSecurityCompactFormat.PUT,
            apdu_head=apdu_head,
        )
        # TODO: Decide what to do based on TAG_FILE_DESCRIPTOR data coding byte
        # on current path (EF, DF and all parents up to root).
        putData = current_file.putData
        for tag, value in tag_list:
            putData(
                tag=tag,
                value=value,
                index=channel.getDataObjectIndex(tag=tag),
            )
        return SUCCESS

    def handleVerify(
        self,
        channel,
        apdu_head,
        is_bertlv,
        command_data,
        response_len,
    ):
        _ = response_len # Silence pylint.
        if is_bertlv:
            # TODO
            raise InstructionNotSupported
        p2 = apdu_head.parameter2
        if (
            apdu_head.parameter1 not in (
                BASIC_SECURITY_P1_NO_INFORMATION,
                BASIC_SECURITY_P1_LOGOUT,
            ) or
            p2 & BASIC_SECURITY_P2_RESERVED_MASK
        ):
            raise WrongParametersP1P2
        if apdu_head.parameter1 == BASIC_SECURITY_P1_LOGOUT:
            if command_data:
                raise WrongLength
            method_id = 'logout'
        else:
            method_id = 'verify'
        if (
            p2 & BASIC_SECURITY_P2_SCOPE_MASK
        ) == BASIC_SECURITY_P2_SCOPE_GLOBAL:
            current_file = self.traverse((MASTER_FILE_IDENTIFIER, ))
        else:
            # Find nearest application in path.
            # Selected file is available if needed through channel.
            for current_file in channel.traverse().iterPath(channel=channel):
                if current_file.isinstance(ApplicationFile):
                    break
        try:
            method = getattr(current_file, method_id)
        except AttributeError:
            raise InstructionIncompatibleWithFile from None
        method(
            channel=channel,
            level=p2 & BASIC_SECURITY_P2_QUALIFIER_MASK,
            command_data=command_data,
        )
        return SUCCESS

    def handleManageSecurityEnvironment(
        self,
        channel,
        apdu_head,
        command_data,
        response_len,
    ):
        _ = response_len # Silence pylint.
        p1 = apdu_head.parameter1
        need_command_data = False
        if p1 == INSTRUCTION_MANAGE_SECURITY_ENVIRONMENT_P1_STORE:
            method_id = 'storeSecurityEnvironment'
        elif p1 == INSTRUCTION_MANAGE_SECURITY_ENVIRONMENT_P1_RESTORE:
            method_id = 'restoreSecurityEnvironment'
        elif p1 == INSTRUCTION_MANAGE_SECURITY_ENVIRONMENT_P1_ERASE:
            method_id = 'eraseSecurityEnvironment'
        elif (
            p1 & INSTRUCTION_MANAGE_SECURITY_ENVIRONMENT_P1_SET_ACTION_MASK
        ) == INSTRUCTION_MANAGE_SECURITY_ENVIRONMENT_P1_SET:
            method_id = 'setSecurityEnvironment'
            need_command_data = True
        current_file = channel.traverse()
        try:
            method = getattr(current_file, method_id)
        except AttributeError:
            raise WrongParametersP1P2 from None
        kw = {}
        if need_command_data:
            kw['control_reference_value_list'] = list(CodecBER.iterDecode(
                value=command_data,
                # XXX: better schema: a4, a6, aa, b4, b6, b8
                # (AT, KAT, HT, CCT, DST, CT)
                schema=AllSchema,
            ))
        elif command_data:
            raise WrongParameterInCommandData
        method(
            channel=channel,
            secure_messaging_command=p1 & INSTRUCTION_MANAGE_SECURITY_ENVIRONMENT_P1_SET_SUBJECT_SECURE_MESSAGING_COMMAND,
            secure_messaging_response=p1 & INSTRUCTION_MANAGE_SECURITY_ENVIRONMENT_P1_SET_SUBJECT_SECURE_MESSAGING_RESPONSE,
            decipher=p1 & INSTRUCTION_MANAGE_SECURITY_ENVIRONMENT_P1_SET_SUBJECT_DECIPHER,
            encipher=p1 & INSTRUCTION_MANAGE_SECURITY_ENVIRONMENT_P1_SET_SUBJECT_ENCIPHER,
            control_reference=apdu_head.parameter2,
            **kw
        )
        return SUCCESS

    def handleChangeReferenceData(
        self,
        channel,
        apdu_head,
        command_data,
        response_len,
    ):
        _ = response_len # Silence pylint.
        p1 = apdu_head.parameter1
        if p1 not in (0, 1):
            raise WrongParametersP1P2
        p2 = apdu_head.parameter2
        if (
            p2 & BASIC_SECURITY_P2_SCOPE_MASK
        ) == BASIC_SECURITY_P2_SCOPE_GLOBAL:
            current_file = self.traverse((MASTER_FILE_IDENTIFIER, ))
        else:
            # Find nearest application in path.
            # Selected file is available if needed through channel.
            for current_file in channel.traverse().iterPath(channel=channel):
                if current_file.isinstance(ApplicationFile):
                    break
        try:
            changeReferenceData = current_file.changeReferenceData
        except AttributeError:
            raise InstructionIncompatibleWithFile from None
        changeReferenceData(
            channel=channel,
            new_only=p1 == 1,
            level=p2 & BASIC_SECURITY_P2_QUALIFIER_MASK,
            command_data=command_data,
        )
        return SUCCESS

    def handlePerformSecurityOperation(
        self,
        channel,
        apdu_head,
        command_data,
        response_len,
    ):
        current_file = channel.traverse()
        try:
            performSecurityOperation = current_file.performSecurityOperation
        except AttributeError:
            raise InstructionIncompatibleWithFile from None
        return performSecurityOperation(
            channel=channel,
            apdu_head=apdu_head,
            command_data=command_data,
            response_len=response_len,
        )

    def handleGenerateAsymmetricKeyPair(
        self,
        channel,
        apdu_head,
        is_bertlv,
        command_data,
        response_len,
    ):
        _ = response_len # Silence pylint.
        if not is_bertlv:
            raise InstructionNotSupported
        current_file = channel.traverse()
        try:
            method = current_file.generateAsymmetricKeyPair
        except AttributeError:
            raise InstructionIncompatibleWithFile from None
        return method(
            channel=channel,
            p1=apdu_head.parameter1,
            p2=apdu_head.parameter2,
            command_data=command_data,
        )

    def handleInternalAuthenticate(
        self,
        channel,
        apdu_head,
        command_data,
        response_len,
    ):
        _ = response_len # Silence pylint.
        current_file = channel.traverse()
        try:
            method = current_file.internalAuthenticate
        except AttributeError:
            raise InstructionIncompatibleWithFile from None
        return method(
            channel=channel,
            p1=apdu_head.parameter1,
            p2=apdu_head.parameter2,
            command_data=command_data,
        )

    def handleDeactivateFile(
        self,
        channel,
        apdu_head,
        command_data,
        response_len,
    ):
        _ = response_len # Silence pylint.
        if apdu_head.parameter1 or apdu_head.parameter2:
            raise WrongParametersP1P2
        if command_data:
            raise WrongParameterInCommandData
        current_file = channel.traverse()
        if current_file.lifecycle != LifecycleBase.ACTIVATED:
            raise InstructionNotAllowed
        current_file.validate(
            channel=channel,
            permission=FileSecurityCompactFormat.DEACTIVATE,
            apdu_head=apdu_head,
        )
        current_file.deactivate(channel=channel)
        return SUCCESS

    def handleActivateFile(
        self,
        channel,
        apdu_head,
        command_data,
        response_len,
    ):
        _ = response_len # Silence pylint.
        if apdu_head.parameter1 or apdu_head.parameter2:
            raise WrongParametersP1P2
        if command_data:
            raise WrongParameterInCommandData
        current_file = channel.traverse()
        if current_file.lifecycle not in (
            LifecycleBase.CREATION,
            LifecycleBase.INITIALISATION,
            LifecycleBase.DEACTIVATED,
        ):
            raise InstructionNotAllowed
        current_file.validate(
            channel=channel,
            permission=FileSecurityCompactFormat.ACTIVATE,
            apdu_head=apdu_head,
        )
        current_file.activate(channel=channel)
        return SUCCESS

    def handleTerminateDedicatedFile(
        self,
        channel,
        apdu_head,
        command_data,
        response_len,
    ):
        _ = response_len # Silence pylint.
        if apdu_head.parameter1 or apdu_head.parameter2:
            raise WrongParametersP1P2
        if command_data:
            raise WrongParameterInCommandData
        current_file = channel.traverse()
        if (
            not current_file.isinstance(DedicatedFile) or
            current_file.isinstance(MasterFile)
        ):
            raise InstructionIncompatibleWithFile
        current_file.validate(
            channel=channel,
            permission=FileSecurityCompactFormat.TERMINATE,
            apdu_head=apdu_head,
        )
        current_file.terminate(channel=channel)
        return SUCCESS

    def handleTerminateElementaryFile(
        self,
        channel,
        apdu_head,
        command_data,
        response_len,
    ):
        _ = response_len # Silence pylint.
        if apdu_head.parameter1 or apdu_head.parameter2:
            raise WrongParametersP1P2
        if command_data:
            raise WrongParameterInCommandData
        current_file = channel.traverse()
        if not current_file.isinstance(ElementaryFile):
            raise NoCurrentElementaryFile
        current_file.validate(
            channel=channel,
            permission=FileSecurityCompactFormat.TERMINATE,
            apdu_head=apdu_head,
        )
        current_file.terminate(channel=channel)
        return SUCCESS

    def handleTerminateCard(
        self,
        channel,
        apdu_head,
        command_data,
        response_len,
    ):
        _ = response_len # Silence pylint.
        if apdu_head.parameter1 or apdu_head.parameter2:
            raise WrongParametersP1P2
        if command_data:
            raise WrongParameterInCommandData
        root = self.traverse((MASTER_FILE_IDENTIFIER, ))
        root.validate(
            channel=channel,
            permission=FileSecurityCompactFormat.TERMINATE,
            apdu_head=apdu_head,
        )
        if self.__terminate_blanks:
            self.blank()
        else:
            # Terminating Master File terminates the card
            root.terminate(channel=channel)
        return SUCCESS

    def handleResetRetryCounter(
        self,
        channel,
        apdu_head,
        command_data,
        response_len,
    ):
        _ = response_len # Silence pylint.
        current_file = channel.traverse()
        try:
            method = current_file.resetRetryCounter
        except AttributeError:
            raise InstructionIncompatibleWithFile from None
        method(
            channel=channel,
            p1=apdu_head.parameter1,
            p2=apdu_head.parameter2,
            command_data=command_data,
        )
        return SUCCESS

    def handleGetChallenge(
        self,
        channel,
        apdu_head,
        command_data,
        response_len,
    ):
        current_file = channel.traverse()
        try:
            method = current_file.getChallenge
        except AttributeError:
            raise InstructionIncompatibleWithFile from None
        return method(
            channel=channel,
            p1=apdu_head.parameter1,
            p2=apdu_head.parameter2,
            command_data=command_data,
            response_len=response_len,
        )

    def runAPDU(self, command):
        """
        Run provided Application Protocol Data Unit.
        """
        try:
            if (
                self.__root.lifecycle & LifecycleBase.TERMINATED_MASK
            ) == LifecycleBase.TERMINATED:
                raise SecurityNotSatisfied
            with transaction_manager:
                result = self._runAPDU(command)
        except APDUException as exc:
            if logger.isEnabledFor(logging.DEBUG):
                logger.debug('APDU exception', exc_info=True)
            else:
                logger.info('APDU exception %r', exc)
            result = exc.value
            logger.debug('APDU response len=%s value=%s', len(result), result.hex())
        # XXX: convert ZODB errors (ex: POSKeyError) into ErrorPersistentChangedMemoryFailure ?
        except Exception: # pylint: disable=broad-except
            logger.error(
                'APDU processing raised an unhandled exception',
                exc_info=1,
            )
            result = UnspecifiedError().value
            logger.debug('APDU response len=%s value=%s', len(result), result.hex())
        return result

    def _runAPDU(self, command):
        head, command_data, response_len = decodeAPDU(command)
        if head.klass & CLASS_TYPE_MASK == CLASS_TYPE_PROPRIETARY:
            raise ClassNotSupported('proprietary %02x' % (head.klass & ~CLASS_TYPE_MASK))
        klass = head.klass
        if klass & CLASS_STANDARD_FIRST_MASK == CLASS_STANDARD_FIRST:
            is_chain_final = (
                klass & CLASS_STANDARD_FIRST_CHAINING_MASK
            ) == CLASS_STANDARD_FIRST_CHAINING_FINAL
            final_head = APDUHead.from_buffer_copy(command)
            final_head.klass &= ~CLASS_STANDARD_FIRST_CHAINING_MASK
            channel_number = klass & CLASS_STANDARD_FIRST_CHAN_MASK
            secure = CLASS_STANDARD_FIRST_SECURE_DICT[
                klass & CLASS_STANDARD_FIRST_SECURE_MASK
            ]
        elif len(self._v_s_channel_list) > 4 and (
            klass & CLASS_STANDARD_FURTHER_MASK
        ) == CLASS_STANDARD_FURTHER:
            is_chain_final = (
                klass & CLASS_STANDARD_FURTHER_CHAINING_MASK
            ) == CLASS_STANDARD_FURTHER_CHAINING_FINAL
            final_head = APDUHead.from_buffer_copy(command)
            final_head.klass &= ~CLASS_STANDARD_FURTHER_CHAINING_MASK
            channel_number = 4 + (klass & CLASS_STANDARD_FURTHER_CHAN_MASK)
            secure = CLASS_STANDARD_FURTHER_SECURE_DICT[
                klass & CLASS_STANDARD_FURTHER_SECURE_MASK
            ]
        else:
            raise ClassNotSupported('unknown head format %02x' % head.klass)
        instruction = head.instruction & ~INSTRUCTION_BERTLV_MASK
        is_bertlv = head.instruction & INSTRUCTION_BERTLV_MASK == INSTRUCTION_BERTLV
        instruction_supports_bertlv = instruction in BERTLV_SUPPORT_SET
        if is_bertlv and not instruction_supports_bertlv:
            raise InstructionNotSupported
        p1 = head.parameter1
        p2 = head.parameter2
        logger.debug(
            'APDU request %s %s chan=%i %s bertlv=%r p1=%02x p2=%02x command=%s response_len=%02x',
            'final' if is_chain_final else 'chained',
            {
                SECURE_NONE: 'SECURE_NONE',
                SECURE_PROPRIETARY: 'SECURE_PROPRIETARY',
                SECURE_STANDARD_UNAUTH_HEAD: 'SECURE_STANDARD_UNAUTH_HEAD',
                SECURE_STANDARD_AUTH_HEAD: 'SECURE_STANDARD_AUTH_HEAD',
            }[secure],
            channel_number,
            ALL_INSTRUCTION_DICT.get(instruction, '%02x' % instruction),
            is_bertlv,
            p1,
            p2,
            command_data.hex(),
            response_len,
        )
        try:
            channel = self._v_s_channel_list[channel_number]
        except IndexError:
            raise ClassLogicalChannelUnsupported from None
        if not is_chain_final and self._v_s_apdu_chaining_head is None:
            # Begin an APDU chain
            self._v_s_apdu_chaining_head = final_head
            assert not self._v_s_apdu_chaining
        if self._v_s_apdu_chaining_head is not None:
            if final_head != self._v_s_apdu_chaining_head:
                # Head changed mid-chain, complain.
                try:
                    raise ClassChainContinuationUnsupported(
                        dumpAPDUHead(final_head),
                        dumpAPDUHead(self._v_s_apdu_chaining_head),
                    )
                finally:
                    self._clearAPDUChaining()
            self._v_s_apdu_chaining.append(command_data)
            if is_chain_final:
                command_data = chainBytearrayList(self._v_s_apdu_chaining)
                self._clearAPDUChaining()
            else:
                logger.debug('APDU chain still going, intermediate SUCCESS')
                return SUCCESS
        if secure is not SECURE_NONE:
            # TODO: support secure messaging
            raise ClassSecureMessagingUnsupported
        # SELECT may implicitly open class' channel.
        if instruction == INSTRUCTION_SELECT:
            result = self.handleSelect(
                channel=channel,
                apdu_head=head,
                command_data=command_data,
                response_len=response_len,
            )
        else:
            # All other commands must be issued on an opened channel.
            if channel.dedicated_file_path is None:
                raise ClassLogicalChannelUnsupported
            queued_len = channel.getQueuedLen()
            if instruction == INSTRUCTION_GET_RESPONSE:
                if not queued_len:
                    raise InstructionConditionsOfUseNotSatisfied
                if command_data:
                    raise WrongParameterInCommandData
                if p1 or p2:
                    raise WrongParametersP1P2
                result = channel.dequeue(response_len)
            else:
                if queued_len:
                    raise InstructionConditionsOfUseNotSatisfied
                try:
                    handler = getattr(
                        self,
                        INSTRUCTION_METHOD_ID_DICT[instruction],
                    )
                except (KeyError, AttributeError):
                    raise InstructionNotSupported from None
                if instruction_supports_bertlv:
                    result = handler(
                        channel=channel,
                        apdu_head=head,
                        is_bertlv=is_bertlv,
                        command_data=command_data,
                        response_len=response_len,
                    )
                else:
                    result = handler(
                        channel=channel,
                        apdu_head=head,
                        command_data=command_data,
                        response_len=response_len,
                    )
        if len(result) - 2 > response_len:
            logger.debug('APDU response too long, stashing %s bytes', len(result) - 2)
            channel.queue(result)
            result = channel.dequeue(response_len)
        logger.debug('APDU response len=%s value=%s', len(result), result.hex())
        return bytearray(result)

from ._version import get_versions
__version__ = get_versions()['version']
del get_versions
