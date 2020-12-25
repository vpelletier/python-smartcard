# Copyright (C) 2020  Vincent Pelletier <plr.vincent@gmail.com>
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

#pylint: disable=arguments-differ

from collections import defaultdict
import itertools
from .asn1 import (
    AllSchema,
    CLASS_APPLICATION,
    CLASS_CONTEXT,
    Integer,
    IntegerBase,
    ObjectIdentifier,
    OctetString,
    OctetStringBase,
    TypeBase,
    TypeListBase,
    TypeUniveralSimpleBase,
)
from .utils import (
    bitpos,
    NamedSingleton,
)

MASTER_FILE_IDENTIFIER = b'\x3f\x00'
CURRENT_DEDICATED_FILE = b'\x3f\xff'
CURRENT_ELEMENTARY_FILE = b'\x00\x00'
EF_DIR_IDENTIFIER = b'\x2f\x00'
EF_DIR_SHORT_IDENTIFIER = b'\x30'
EF_ATR_IDENTIFIER = b'\x2f\x01'
EF_GDO_IDENTIFIER = b'\x2f\x02'
EF_ARR_IDENTIFIER = b'\x2f\x06'

#
#   Abstract tag classes
#

class TypeApplicationBase(TypeBase): #pylint: disable=abstract-method
    klass = CLASS_APPLICATION

class TypeApplicationSimpleBase(TypeApplicationBase): #pylint: disable=abstract-method
    is_composite = False

class TypeApplicationCompositeBase(TypeListBase): #pylint: disable=abstract-method
    klass = CLASS_APPLICATION

class TypeApplicationCompositeAnyContentBase(TypeApplicationCompositeBase):
    @classmethod
    def iterItemSchema(cls):
        return itertools.cycle([AllSchema])

class TagAllocationAuthorityIdentifier(TypeApplicationCompositeBase):
    @classmethod
    def iterItemSchema(cls):
        return [{
            x.asTagTuple(): x
            for x in (
                ObjectIdentifier,
                Country,
                IssuerIdentificationNumber,
                ApplicationIdentifier,
            )
        }]

class TypeContextBase(TypeBase): #pylint: disable=abstract-method
    klass = CLASS_CONTEXT

class TypeContextSimpleBase(TypeContextBase): #pylint: disable=abstract-method
    is_composite = False

class TypeContextCompositeBase(TypeListBase): #pylint: disable=abstract-method
    klass = CLASS_CONTEXT
    is_composite = True

class LifecycleBase(TypeBase):
    is_composite = False
    NO_INFO = 0
    CREATION = 0x01
    INITIALISATION = 0x03
    OPERATIONAL_MASK = 0xfc
    OPERATIONAL = 0x04
    ACTIVATED_MASK = 0xfd
    ACTIVATED = 0x05
    DEACTIVATED = 0x04
    TERMINATED_MASK = 0xfc
    TERMINATED = 0x0c

    @classmethod
    def encode(cls, value, codec):
        return value.to_bytes(1, 'big')

    @classmethod
    def decode(cls, value, codec):
        if len(value) != 1:
            raise ValueError
        return int.from_bytes(value, 'big')

class TypeApplicationString(OctetStringBase):
    klass = CLASS_APPLICATION

class TypeApplicationInteger(IntegerBase):
    klass = CLASS_APPLICATION

class NotImplementedBase: #pylint: disable=abstract-method
    @classmethod
    def encode(cls, value, codec):
        raise NotImplementedError

    @classmethod
    def decode(cls, value, codec):
        raise NotImplementedError

#
#   Concrete tag classes (including not-implemented-yet)
#

#TAG_INITIAL_ACCESS_DATA                                     = (BERTLV_CLASS_APPLICATION, BERTLV_ENCODING_PLAIN, 0x04)
#TAG_INITIAL_ACCESS_DATA_BYTE_0_OF_2_EF_STRUCTURE_TRANSPARENT = 0x80
#TAG_PRE_ISSUING_DATA                                        = (BERTLV_CLASS_APPLICATION, BERTLV_ENCODING_PLAIN, 0x06)
#TAG_CARD_EXPIRATION_DATE                                    = (BERTLV_CLASS_APPLICATION, BERTLV_ENCODING_PLAIN, 0x19)
#TAG_APPLICATION_EXPIRATION_DATE                             = (BERTLV_CLASS_APPLICATION, BERTLV_ENCODING_PLAIN, 0x24)
#TAG_PROFILE_DATA                                            = (BERTLV_CLASS_APPLICATION, BERTLV_ENCODING_PLAIN, 0x29)
#TAG_CERTIFICATE_HOLDER_AUTHORISATION                        = (BERTLV_CLASS_APPLICATION, BERTLV_ENCODING_PLAIN, 0x4c)
#TAG_CARDHOLDER_RELATED_DATA                                 = (BERTLV_CLASS_APPLICATION, BERTLV_ENCODING_BERTLV, 0x05)
#TAG_CARD_DATA                                               = (BERTLV_CLASS_APPLICATION, BERTLV_ENCODING_BERTLV, 0x06)
#TAG_AUTHENTICATION_DATA                                     = (BERTLV_CLASS_APPLICATION, BERTLV_ENCODING_BERTLV, 0x07)
#TAG_VERIFICATION_DATA_OBJECT                                = (BERTLV_CLASS_APPLICATION, BERTLV_ENCODING_BERTLV, 0x2e)

class Country(NotImplementedBase, TypeApplicationSimpleBase): #pylint: disable=abstract-method
    identifier = 0x01

class IssuerIdentificationNumber(NotImplementedBase, TypeApplicationSimpleBase): #pylint: disable=abstract-method
    identifier = 0x02

class CardServiceData(TypeUniveralSimpleBase):
    identifier = 0x03

    __SELECT_FULL_DF_NAME = 0x80
    __SELECT_PARTIAL_DF_NAME = 0x40
    __EF_DIR_BERTLV = 0x20
    __EF_ATR_BERTLV = 0x10
    EF_DIR_EF_ATR_ACCESS_MODE_READ_BINARY = NamedSingleton('EF_DIR_EF_ATR_ACCESS_MODE_READ_BINARY')
    EF_DIR_EF_ATR_ACCESS_MODE_READ_RECORD = NamedSingleton('EF_DIR_EF_ATR_ACCESS_MODE_READ_RECORD')
    EF_DIR_EF_ATR_ACCESS_MODE_GET_DATA = NamedSingleton('EF_DIR_EF_ATR_ACCESS_MODE_GET_DATA')
    __EF_DER_EF_ATR_ACCESS_MODE_MASK = 0xe
    __EF_DER_EF_ATR_ACCESS_MODE_DICT = {
        EF_DIR_EF_ATR_ACCESS_MODE_READ_BINARY: 0x08,
        EF_DIR_EF_ATR_ACCESS_MODE_READ_RECORD: 0x00,
        EF_DIR_EF_ATR_ACCESS_MODE_GET_DATA: 0x04,
    }
    __EF_DER_EF_ATR_ACCESS_MODE_REVERSE_DICT = {
        value: key
        for key, value in __EF_DER_EF_ATR_ACCESS_MODE_DICT.items()
    }
    __EF_DIR_EF_ATR_ACCESS_MODE_MASK = 0x0e
    __CARD_LACKS_MASTER_FILE = 0x01

    @classmethod
    def encode(cls, value, codec):
        return (
            (cls.__SELECT_FULL_DF_NAME if value['can_select_full_df_name'] else 0) |
            (cls.__SELECT_PARTIAL_DF_NAME if value['can_select_partial_df_name'] else 0) |
            (cls.__EF_DIR_BERTLV if value['ef_dir_is_bertlv'] else 0) |
            (cls.__EF_ATR_BERTLV if value['ef_atr_is_bertlv'] else 0) |
            cls.__EF_DER_EF_ATR_ACCESS_MODE_DICT[value['ef_dir_ef_atr_access_mode']] |
            (0 if value['has_master_file'] else cls.__CARD_LACKS_MASTER_FILE)
        ).to_bytes(1, 'big')

    @classmethod
    def decode(cls, value, codec):
        if len(value) != 1:
            raise ValueError
        value = int.from_bytes(value, 'big')
        return {
            'can_select_full_df_name': bool(value & cls.__SELECT_FULL_DF_NAME),
            'can_select_partial_df_name': bool(value & cls.__SELECT_PARTIAL_DF_NAME),
            'ef_dir_is_bertlv': bool(value & cls.__EF_DIR_BERTLV),
            'ef_atr_is_bertlv': bool(value & cls.__EF_ATR_BERTLV),
            'ef_dir_ef_atr_access_mode': cls.__EF_DER_EF_ATR_ACCESS_MODE_REVERSE_DICT[
                value & cls.__EF_DER_EF_ATR_ACCESS_MODE_MASK
            ],
            'has_master_file': not value & cls.__CARD_LACKS_MASTER_FILE,
        }

__DATA_CODING_BYTE_EF_WITH_TLV_CONTENT = 0x80
WRITE_FUNCTION_ONE_TIME = NamedSingleton('WRITE_FUNCTION_ONE_TIME')
WRITE_FUNCTION_PROPRIETARY = NamedSingleton('WRITE_FUNCTION_PROPRIETARY')
WRITE_FUNCTION_OR = NamedSingleton('WRITE_FUNCTION_OR')
WRITE_FUNCTION_AND = NamedSingleton('WRITE_FUNCTION_AND')
__DATA_CODING_BYTE_WRITE_FUNCTION_DICT = {
    WRITE_FUNCTION_ONE_TIME:             0x00,
    WRITE_FUNCTION_PROPRIETARY:          0x20,
    WRITE_FUNCTION_OR:                   0x40,
    WRITE_FUNCTION_AND:                  0x60,
}
__DATA_CODING_BYTE_WRITE_FUNCTION_REVERSE_DICT = {
    value: key
    for key, value in __DATA_CODING_BYTE_WRITE_FUNCTION_DICT.items()
}
__DATA_CODING_BYTE_WRITE_FUNCTION_MASK = 0x60
__DATA_CODING_BYTE_FF_TAG =              0x10
def getDataCodingByte(
    supports_ef_with_tlv_content,
    write_function_behaviour,
    supports_ff_tag,
    size_unit,
):
    size_unit_po2 = bitpos(size_unit)
    if size_unit_po2 > 0xf:
        raise ValueError
    return (
        (__DATA_CODING_BYTE_EF_WITH_TLV_CONTENT if supports_ef_with_tlv_content else 0) |
        __DATA_CODING_BYTE_WRITE_FUNCTION_DICT[write_function_behaviour] |
        (__DATA_CODING_BYTE_FF_TAG if supports_ff_tag else 0) |
        size_unit_po2
    )

def getWriteFunctionFromDataCodingByte(data_coding_byte):
    return __DATA_CODING_BYTE_WRITE_FUNCTION_REVERSE_DICT[
        data_coding_byte & __DATA_CODING_BYTE_WRITE_FUNCTION_MASK
    ]

class CardCapabilities(TypeUniveralSimpleBase):
    identifier = 0x07

    __BYTE_0_SELECT_FULL_DF_NAME =        0x800000
    __BYTE_0_SELECT_PARTIAL_DF_NAME =     0x400000
    __BYTE_0_SELECT_PATH =                0x200000
    __BYTE_0_SELECT_FILE_IDENTIFIER =     0x100000
    __BYTE_0_IMPLICIT_DF_SELECTION =      0x080000
    __BYTE_0_SHORT_EF_IDENTIFIER =        0x040000
    __BYTE_0_RECORD_NUMBER =              0x020000
    __BYTE_0_RECORD_IDENTIFIER =          0x010000
    __BYTE_2_COMMAND_CHAINING =           0x000080
    __BYTE_2_EXTENDED_LENGTHS =           0x000040
    __BYTE_2_EXTENDED_LENGTHS_EF_ATR =    0x000020
    __BYTE_2_CHANNEL_ASSIGNMENT_BY_CARD = 0x000010
    __BYTE_2_CHANNEL_ASSIGNMENT_BY_HOST = 0x000008
    __BYTE_2_CHANNEL_COUNT_MAX =          0x000007 # 0..6 maps to 1..7, 7 means >=8
    __BYTE_2_CHANNEL_COUNT_MASK =         0x000007

    @classmethod
    def encode(cls, value, codec):
        if not 0 <= value['data_coding_byte'] < 0x100:
            raise ValueError
        return (
            (cls.__BYTE_0_SELECT_FULL_DF_NAME if value['can_select_full_df_name'] else 0) |
            (cls.__BYTE_0_SELECT_PARTIAL_DF_NAME if value['can_select_partial_df_name'] else 0) |
            (cls.__BYTE_0_SELECT_PATH if value['can_select_path'] else 0) |
            (cls.__BYTE_0_SELECT_FILE_IDENTIFIER if value['can_select_file_identifier'] else 0) |
            (cls.__BYTE_0_IMPLICIT_DF_SELECTION if value['has_implicit_df_selection'] else 0) |
            (cls.__BYTE_0_SHORT_EF_IDENTIFIER if value['supports_short_ef_identifier'] else 0) |
            (cls.__BYTE_0_RECORD_NUMBER if value['supports_record_number'] else 0) |
            (cls.__BYTE_0_RECORD_IDENTIFIER if value['supports_record_identifier'] else 0) |
            (value['data_coding_byte'] << 8) |
            (cls.__BYTE_2_COMMAND_CHAINING if value['supports_command_chaining'] else 0) |
            (cls.__BYTE_2_EXTENDED_LENGTHS if value['supports_extended_lenghts'] else 0) |
            (cls.__BYTE_2_EXTENDED_LENGTHS_EF_ATR if value['extended_lengths_ef_atr'] else 0) |
            (cls.__BYTE_2_CHANNEL_ASSIGNMENT_BY_CARD if value['channel_assignment_by_card'] else 0) |
            (cls.__BYTE_2_CHANNEL_ASSIGNMENT_BY_HOST if value['channel_assignment_by_host'] else 0) |
            min(0x07, max(0, value['channel_count'] - 1))
        ).to_bytes(3, 'big')

    @classmethod
    def decode(cls, value, codec):
        if len(value) != 3:
            raise ValueError
        return {
            'can_select_full_df_name':      bool(value[0] & cls.__BYTE_0_SELECT_FULL_DF_NAME),
            'can_select_partial_df_name':   bool(value[0] & cls.__BYTE_0_SELECT_PARTIAL_DF_NAME),
            'can_select_path':              bool(value[0] & cls.__BYTE_0_SELECT_PATH),
            'can_select_file_identifier':   bool(value[0] & cls.__BYTE_0_SELECT_FILE_IDENTIFIER),
            'has_implicit_df_selection':    bool(value[0] & cls.__BYTE_0_IMPLICIT_DF_SELECTION),
            'supports_short_ef_identifier': bool(value[0] & cls.__BYTE_0_SHORT_EF_IDENTIFIER),
            'supports_record_number':       bool(value[0] & cls.__BYTE_0_RECORD_NUMBER),
            'supports_record_identifier':   bool(value[0] & cls.__BYTE_0_RECORD_IDENTIFIER),
            'data_coding_byte': value[1],
            'supports_command_chaining':    bool(value[2] & cls.__BYTE_2_COMMAND_CHAINING),
            'supports_extended_lenghts':    bool(value[2] & cls.__BYTE_2_EXTENDED_LENGTHS),
            'extended_lengths_ef_atr':      bool(value[2] & cls.__BYTE_2_EXTENDED_LENGTHS_EF_ATR),
            'channel_assignment_by_card':   bool(value[2] & cls.__BYTE_2_CHANNEL_ASSIGNMENT_BY_CARD),
            'channel_assignment_by_host':   bool(value[2] & cls.__BYTE_2_CHANNEL_ASSIGNMENT_BY_HOST),
            'channel_count': (value[2] & 0x07) + 1,
        }

class CardLifecycle(LifecycleBase):
    klass = CLASS_APPLICATION
    identifier = 0x08

class ExtendedHeaderList(TypeApplicationString):
    identifier = 0x0d

class ApplicationIdentifier(TypeApplicationString):
    identifier = 0x0f

class ApplicationLabel(TypeApplicationString):
    # XXX: encoding ?
    identifier = 0x10

class FileReference(TypeApplicationSimpleBase):
    identifier = 0x11

    @classmethod
    def encode(cls, value, codec):
        if not value:
            raise ValueError
        length = len(value)
        if length == 1:
            if value[0] == MASTER_FILE_IDENTIFIER:
                value = []
            else:
                short_identifier = value[0]
                if short_identifier & 0x7:
                    raise ValueError
                if short_identifier & 0xf8 == 0xf8:
                    raise ValueError
        return b''.join(value)

    @classmethod
    def decode(cls, value, codec):
        if not value:
            return [MASTER_FILE_IDENTIFIER]
        length = len(value)
        if length == 1:
            short_identifier = value[0]
            if short_identifier & 0x7:
                raise ValueError
            if short_identifier & 0xf8 == 0xf8:
                raise ValueError
            return [value]
        result = []
        for offset in range(0, length, 2):
            result.append(value[offset:offset + 2])
        return result

class CommandAPDU(NotImplementedBase, TypeApplicationSimpleBase): #pylint: disable=abstract-method
    identifier = 0x12

class DiscretionaryData(NotImplementedBase, TypeApplicationSimpleBase): #pylint: disable=abstract-method
    identifier = 0x13

class OffsetData(TypeApplicationInteger):
    identifier = 0x14

class CardSerialNumber(TypeApplicationString):
    identifier = 0x1a

class Name(TypeApplicationString):
    identifier = 0x1b

class TagList(TypeApplicationSimpleBase):
    identifier  = 0x1c

    @classmethod
    def encode(cls, value, codec):
        return b''.join(codec.encodeTag(tag) for tag in value)

    @classmethod
    def decode(cls, value, codec):
        return list(codec.iterDecodeTag(value=value, schema=AllSchema))

class TagHeaderList(TypeApplicationSimpleBase):
    identifier = 0x1d

    @classmethod
    def encode(cls, value, codec):
        return b''.join(
            codec.encodeTagLength(tag, length)
            for tag, length in value
        )

    @classmethod
    def decode(cls, value, codec):
        return list(codec.iterDecodeTagLength(value=value, schema=AllSchema))

class ApplicationExpirationDate(NotImplementedBase, TypeApplicationSimpleBase): #pylint: disable=abstract-method
    identifier = 0x24

class ElementList(NotImplementedBase, TypeApplicationSimpleBase): #pylint: disable=abstract-method
    identifier = 0x41

class URL(TypeApplicationString):
    identifier = 0x50

class AnswerToReset(TypeApplicationString):
    identifier = 0x51

class HistoricalData(TypeApplicationString):
    identifier = 0x52

# Used as a command value wrapper in SELECT DATA

class ApplicationTemplate(TypeApplicationCompositeBase):
    identifier = 0x01

    @classmethod
    def iterItemSchema(cls):
        return itertools.cycle([{
            x.asTagTuple(): x
            for x in (
                ApplicationIdentifier,
                ApplicationLabel,
                FileReference,
                CommandAPDU,
                DiscretionaryData,
                DiscretionaryTemplate,
                URL,
                ApplicationTemplate,
            )
        }])

class FileControlParameterTemplate(TypeApplicationCompositeBase):
    identifier = 0x02

    @classmethod
    def iterItemSchema(cls):
        return itertools.cycle([{
            x.asTagTuple(): x
            for x in (
                FileSize,
                FileStorageUsage,
                FileDescriptor,
                FileIdentifier,
                FileName, # DF only
                FileProprietaryInformation,
                FileSecurityProprietary,
                FileExtendedControlInvormationElementaryFileId,
                FileShortIdentifier, # EF only
                Lifecycle,
                FileSecurityExpandedFormatReference,
                FileSecurityCompactFormat,
                FileSecurityEnvironmentTemplateElementaryFileId,
                FileChannelSecurity,
                FileDataObjectSecurityTemplate,
                FileDataObjectSecurityProprietary,
                FileShortIdentifierToFileReferenceMapping,
                FileProprietaryInformationComposite,
                FileSecurityTemplateExpandedFormat,
                CryptographicIdentifierTemplate,
            )
        }])

class Wrapper(TypeApplicationCompositeBase):
    identifier = 0x03

    @classmethod
    def iterItemSchema(cls):
        return [
            {
                x.asTagTuple(): x
                for x in (
                    ElementList,
                    TagList,
                    TagHeaderList,
                )
            },
            {
                x.asTagTuple(): x
                for x in (
                    FileReference,
                    CommandAPDU,
                )
            },
        ]

class FileManagementTemplate(TypeApplicationCompositeBase):
    identifier = 0x04

    @classmethod
    def iterItemSchema(cls):
        return itertools.cycle([{
            x.asTagTuple(): x
            for x in (
                ApplicationIdentifier,
                ApplicationLabel,
                FileReference,
                ApplicationExpirationDate,
                DiscretionaryData,
                DiscretionaryTemplate,
                URL,
            )
        }])

class CardholderData(TypeApplicationCompositeAnyContentBase):
    identifier = 0x05

class ApplicationRelatedData(TypeApplicationCompositeAnyContentBase):
    identifier = 0x0e

class FileControlParametersAndManagementData(TypeApplicationCompositeBase):
    identifier = 0x0f

    @classmethod
    def iterItemSchema(cls):
        return itertools.cycle([{
            x.asTagTuple(): x
            for x in (
                FileControlParameterTemplate,
                FileManagementTemplate,
            )
        }])

class InterindustryTemplate(TypeApplicationCompositeAnyContentBase):
    identifier = 0x10

class DiscretionaryTemplate(TypeApplicationCompositeAnyContentBase):
    identifier = 0x13

class CompatibleTagAllocationAuthorityIdentifier(TagAllocationAuthorityIdentifier):
    identifier = 0x18

class CoexistentTagAllocationAuthorityIdentifier(TagAllocationAuthorityIdentifier):
    identifier = 0x19

class SecuritySupportTemplate(TypeApplicationCompositeBase):
    identifier = 0x1a

    @classmethod
    def iterItemSchema(cls):
        return itertools.cycle([{
            x.asTagTuple(): x
            for x in (
                CardSessionCounter,
                CardSessionIdentifier,
                #FileSelectionCounter, # context, simple, identifier 2 to e
                SignatureCounter,
                #InternalProgressionValue, # context, simple, identifier 20 to 2f
                #ExternalProgressionValue, # context, simple, identifier 30 to 3f
            )
        }])

class CardSessionCounter(Integer):
    klass = CLASS_CONTEXT
    identifier = 0x00

class CardSessionIdentifier(NotImplementedBase, TypeContextSimpleBase): #pylint: disable=abstract-method
    identifier = 0x01

class SignatureCounter(Integer):
    klass = CLASS_CONTEXT
    identifier = 0x13

class FileSecurityEnvironmentTemplate(NotImplementedBase, TypeApplicationCompositeBase): #pylint: disable=abstract-method
    identifier = 0x1b

    @classmethod
    def iterItemSchema(cls):
        return itertools.cycle([{
            x.asTagTuple(): x
            for x in (
                SecurityEnvironmentIdentifier,
                Lifecycle,
                CryptographicIdentifierTemplate,
                # a{4,6,a},b{4,6,8}
            )
        }])

class SecurityEnvironmentIdentifier(TypeContextSimpleBase):
    identifier = 0x00

    @classmethod
    def encode(cls, value, codec):
        return value.to_bytes(1, 'big')

    @classmethod
    def decode(cls, value, codec):
        if len(value) != 1:
            raise ValueError
        return int.from_bytes(value, 'big')

class DynamicAuthenticationTemplate(NotImplementedBase, TypeContextSimpleBase): #pylint: disable=abstract-method
    identifier = 0x1c

class SecureMessageTemplate(NotImplementedBase, TypeContextSimpleBase): #pylint: disable=abstract-method
    identifier = 0x1d

class InterindustryTemplateDataObject(TypeApplicationCompositeAnyContentBase):
    identifier = 0x1e

class CardholderCertificate(TypeApplicationString):
    identifier = 0x21
    is_composite = True # XXX: why is this a composite type ?

class FileSize(Integer):
    klass = CLASS_CONTEXT
    identifier = 0x00

class FileStorageUsage(Integer):
    klass = CLASS_CONTEXT
    identifier = 0x01

class FileDescriptor(TypeContextSimpleBase):
    identifier = 0x02

    ACCESSIBILITY_MASK = 0x40
    ACCESSIBILITY_EXCLUSIVE = 0x00
    ACCESSIBILITY_SHARED = 0x40
    FILE_TYPE_DEDICATED = NamedSingleton('FILE_TYPE_DEDICATED')
    FILE_TYPE_ELEMENTARY_WORKING = NamedSingleton('FILE_TYPE_ELEMENTARY_WORKING')
    FILE_TYPE_ELEMENTARY_INTERNAL = NamedSingleton('FILE_TYPE_ELEMENTARY_INTERNAL')
    __FILE_TYPE_DICT = {
        FILE_TYPE_DEDICATED: 0x38,
        FILE_TYPE_ELEMENTARY_WORKING: 0x00,
        FILE_TYPE_ELEMENTARY_INTERNAL: 0x08,
    }
    __FILE_TYPE_REVERSE_DICT = {
        value: key
        for key, value in __FILE_TYPE_DICT.items()
    }
    __FILE_TYPE_MASK = 0x38
    STRUCTURE_NONE = NamedSingleton('STRUCTURE_NONE')
    STRUCTURE_EF_TRANSPARENT = NamedSingleton('STRUCTURE_EF_TRANSPARENT')
    STRUCTURE_EF_LINEAR_FIXED_SIZE = NamedSingleton('STRUCTURE_EF_LINEAR_FIXED_SIZE')
    STRUCTURE_EF_LINEAR_FIXED_SIZE_COMPOSITE = NamedSingleton('STRUCTURE_EF_LINEAR_FIXED_SIZE_COMPOSITE')
    STRUCTURE_EF_LINEAR_VARIABLE_SIZE = NamedSingleton('STRUCTURE_EF_LINEAR_VARIABLE_SIZE')
    STRUCTURE_EF_LINEAR_VARIABLE_SIZE_COMPOSITE = NamedSingleton('STRUCTURE_EF_LINEAR_VARIABLE_SIZE_COMPOSITE')
    STRUCTURE_EF_CYCLIC_FIXED_SIZE = NamedSingleton('STRUCTURE_EF_CYCLIC_FIXED_SIZE')
    STRUCTURE_EF_CYCLIC_FIXED_SIZE_COMPOSITE = NamedSingleton('STRUCTURE_EF_CYCLIC_FIXED_SIZE_COMPOSITE')
    STRUCTURE_DO_COMPOSITE = NamedSingleton('STRUCTURE_DO_COMPOSITE')
    STRUCTURE_DO_COMPOSITE_SIMPLE = NamedSingleton('STRUCTURE_DO_COMPOSITE_SIMPLE')
    __STRUCTURE_DICT = {
        STRUCTURE_NONE: 0x00,
        STRUCTURE_EF_TRANSPARENT: 0x01,
        STRUCTURE_EF_LINEAR_FIXED_SIZE: 0x02,
        STRUCTURE_EF_LINEAR_FIXED_SIZE_COMPOSITE: 0x03,
        STRUCTURE_EF_LINEAR_VARIABLE_SIZE: 0x04,
        STRUCTURE_EF_LINEAR_VARIABLE_SIZE_COMPOSITE: 0x05,
        STRUCTURE_EF_CYCLIC_FIXED_SIZE: 0x06,
        STRUCTURE_EF_CYCLIC_FIXED_SIZE_COMPOSITE: 0x07,
        STRUCTURE_DO_COMPOSITE: 0x01,
        STRUCTURE_DO_COMPOSITE_SIMPLE: 0x02,
    }
    __STRUCTURE_EF_REVERSE_DICT = {
        0x00: STRUCTURE_NONE,
        0x01: STRUCTURE_EF_TRANSPARENT,
        0x02: STRUCTURE_EF_LINEAR_FIXED_SIZE,
        0x03: STRUCTURE_EF_LINEAR_FIXED_SIZE_COMPOSITE,
        0x04: STRUCTURE_EF_LINEAR_VARIABLE_SIZE,
        0x05: STRUCTURE_EF_LINEAR_VARIABLE_SIZE_COMPOSITE,
        0x06: STRUCTURE_EF_CYCLIC_FIXED_SIZE,
        0x07: STRUCTURE_EF_CYCLIC_FIXED_SIZE_COMPOSITE,
    }
    __STRUCTURE_DF_REVERSE_DICT = {
        0x00: STRUCTURE_NONE,
        0x01: STRUCTURE_DO_COMPOSITE,
        0x02: STRUCTURE_DO_COMPOSITE_SIMPLE,
    }
    __STRUCTURE_MASK = 0x07

    @classmethod
    def encode(cls, value, codec):
        shareable = value['shareable']
        file_type = value['file_type']
        structure = value.get('structure')
        data_coding_byte = value.get('data_coding_byte')
        record_length = value.get('record_length')
        record_count = value.get('record_count')
        try:
            file_type_bin = cls.__FILE_TYPE_DICT[file_type]
        except KeyError:
            if 2 <= file_type < 8:
                file_type_bin = file_type << 3
            else:
                raise ValueError from None
        result = (
            (0x40 if shareable else 0x00) |
            file_type_bin | (
                0x00
                if file_type is cls.FILE_TYPE_DEDICATED else
                cls.__STRUCTURE_DICT[structure]
            )
        ).to_bytes(1, 'big')
        if data_coding_byte is not None:
            result += data_coding_byte.to_bytes(1, 'big')
            if record_length is not None:
                result += record_length.to_bytes(
                    (
                        1
                        if (
                            record_length.bit_count() <= 8 and
                            record_count is None
                        ) else
                        2
                    ),
                    'big',
                )
                if record_count is not None:
                    result += record_count.to_bytes(
                        (
                            1
                            if record_count.bit_count() <= 8 else
                            2
                        ),
                        'big',
                    )
            elif record_count is not None:
                raise ValueError
        elif record_length is not None or record_count is not None:
            raise ValueError
        return result

    @classmethod
    def decode(cls, value, codec):
        file_type = value[0] & cls.__FILE_TYPE_MASK
        try:
            file_type = cls.__FILE_TYPE_REVERSE_DICT[file_type]
        except KeyError:
            file_type >>= 3
        else:
            structure = (
                cls.__STRUCTURE_DF_REVERSE_DICT
                if file_type is cls.FILE_TYPE_DEDICATED else
                cls.__STRUCTURE_EF_REVERSE_DICT
            )[value[0] & 0x7]
        data_length = len(value)
        return {
            'shareable': bool(value[0] & 0x40),
            'file_type': file_type,
            'structure': structure,
            'data_coding_byte': (
                value[1]
                if data_length > 1 else
                None
            ),
            'record_length': (
                int.from_bytes(value[2:4], 'big')
                if data_length > 2 else
                None
            ),
            'record_count': (
                int.from_bytes(value[4:], 'big')
                if data_length > 4 else
                None
            ),
        }

class FileIdentifier(TypeContextSimpleBase):
    identifier = 0x03

    @classmethod
    def encode(cls, value, codec):
        return value.to_bytes(2, 'big')

    @classmethod
    def decode(cls, value, codec):
        if len(value) != 2:
            raise ValueError
        return int.from_bytes(value, 'big')

class FileName(OctetString):
    # DedicatedFile only
    identifier = 0x04

    @classmethod
    def encode(cls, value, codec):
        if len(value) > 16:
            raise ValueError
        return super().encode(value=value, codec=codec)

    @classmethod
    def decode(cls, value, codec):
        result = super().decode(value=value, codec=codec)
        if len(result) > 16:
            raise ValueError
        return result

class FileProprietaryInformation(NotImplementedBase, TypeContextSimpleBase): #pylint: disable=abstract-method
    identifier = 0x05

class FileSecurityProprietary(NotImplementedBase, TypeContextSimpleBase): #pylint: disable=abstract-method
    identifier = 0x06

class FileExtendedControlInvormationElementaryFileId(FileIdentifier):
    identifier = 0x07

class FileShortIdentifier(TypeContextSimpleBase):
    identifier = 0x08

    @classmethod
    def encode(cls, value, codec):
        return value.to_bytes(1, 'big')

    @classmethod
    def decode(cls, value, codec):
        if len(value) != 1:
            raise ValueError
        return int.from_bytes(value, 'big')

class Lifecycle(LifecycleBase):
    klass = CLASS_CONTEXT
    identifier = 0x0a

class FileSecurityExpandedFormatReference(TypeContextSimpleBase):
    identifier = 0x0b

    @classmethod
    def encode(
        cls,
        codec,
        access_rule_record_number=None,
        file_identifier=None,
        security_environment_list=None,
    ):
        if file_identifier is not None and len(file_identifier) != 2:
            raise ValueError
        if security_environment_list is not None:
            if access_rule_record_number is not None:
                raise ValueError
            return file_identifier + b''.join(
                security_environment_id.to_bytes(1, 'big') +
                access_rule_record_number.to_bytes(1, 'big')
                for (
                    security_environment_id,
                    access_rule_record_number,
                ) in security_environment_list
            )
        access_rule_record_number = access_rule_record_number.to_bytes(1, 'big')
        if file_identifier is not None:
            return file_identifier + access_rule_record_number
        return access_rule_record_number

    @classmethod
    def decode(cls, value, codec):
        result = {}
        data_len = len(value)
        if data_len == 1:
            result['access_rule_record_number'] = int.from_bytes(value, 'big')
        else:
            if data_len == 2:
                raise ValueError
            result['file_identifier'] = value[:2]
            if data_len == 3:
                result['access_rule_record_number'] = value[2]
            else:
                result['security_environment_list'] = security_environment_list = []
                value = value[2:]
                while value:
                    security_environment_list.append((value[0], value[1]))
                    value = value[2:]
        return result

class FileSecurityCompactFormat(TypeContextSimpleBase):
    identifier = 0x0c

    DELETE_SELF = NamedSingleton('DELETE_SELF')
    TERMINATE = NamedSingleton('TERMINATE')
    ACTIVATE = NamedSingleton('ACTIVATE')
    DEACTIVATE = NamedSingleton('DEACTIVATE')
    # For Dedicated files
    CREATE_DEDICATED_FILE = NamedSingleton('CREATE_DEDICATED_FILE')
    CREATE_ELEMENTARY_FILE = NamedSingleton('CREATE_ELEMENTARY_FILE')
    DELETE_CHILD = NamedSingleton('DELETE_CHILD')
    # For Elementary files
    EXTEND = NamedSingleton('EXTEND')
    MODIFY = NamedSingleton('MODIFY')
    READ = NamedSingleton('READ')
    # For Data Objects
    MANAGE_SECURITY = NamedSingleton('MANAGE_SECURITY')
    PUT = NamedSingleton('PUT')
    GET = NamedSingleton('GET')
    __MODE_TO_BIT = {
        DELETE_SELF: 0x40,
        TERMINATE: 0x20,
        ACTIVATE: 0x10,
        DEACTIVATE: 0x08,
        MANAGE_SECURITY: 0x04,
        EXTEND: 0x04,
        CREATE_DEDICATED_FILE: 0x04,
        PUT: 0x02,
        MODIFY: 0x02,
        CREATE_ELEMENTARY_FILE: 0x02,
        GET: 0x01,
        READ: 0x01,
        DELETE_CHILD: 0x01,
    }
    __BIT_TO_MODE_SET = defaultdict(set)
    for mode, bit in __MODE_TO_BIT.items():
        __BIT_TO_MODE_SET[bit].add(mode)
    del mode, bit #pylint: disable=undefined-loop-variable

    @classmethod
    def encode(cls, value, codec):
        # XXX: no support for proprietary bits (MSb=1)
        if not value:
            raise ValueError
        mode_bit_to_condition_byte_dict = {
            cls.__MODE_TO_BIT[mode]: condition_byte
            for mode, condition_byte in value.items()
        }
        assert len(mode_bit_to_condition_byte_dict) == len(value), repr(value)
        access_mode = 0
        security_condition_list = []
        for mode_bit, condition_byte in sorted(
            mode_bit_to_condition_byte_dict.items(),
            reverse=True,
        ):
            #if condition_byte == SECURITY_CONDITION_DENY:
            #    continue
            access_mode |= mode_bit
            security_condition_list.append(condition_byte)
        return bytes([access_mode] + security_condition_list)

    @classmethod
    def decode(cls, value, codec):
        result = {}
        mask = 0x40
        index = 1
        while mask:
            if value[0] & mask:
                security_condition = value[index]
                for mode in cls.__BIT_TO_MODE_SET[mask]:
                    result[mode] = security_condition
                index +=1
            mask >>= 1
        return result

SECURITY_CONDITION_ALLOW = 0x00
SECURITY_CONDITION_DENY = 0xff
SECURITY_CONDITION_SECURITY_ENVIRONMENT_MASK = 0x0f
SECURITY_CONDITION_SECURITY_ENVIRONMENT_NONE = 0x00
SECURITY_CONDITION_LOGICAL_MASK = 0x80
SECURITY_CONDITION_LOGICAL_OR = 0x00
SECURITY_CONDITION_LOGICAL_AND = 0x80
SECURITY_CONDITION_USER_AUTHENTICATION = 0x10
SECURITY_CONDITION_EXTERNAL_AUTHENTICATION = 0x20
SECURITY_CONDITION_SECURE_MESSAGING = 0x40
def encodeSecurityConditionByte(
    require_all=True,
    secure_messaging=False,
    external_authentication=False,
    user_authentication=False,
    security_environment_id=0,
):
    if not 0 <= security_environment_id < 0x10:
        raise ValueError
    return (
        (SECURITY_CONDITION_LOGICAL_AND if require_all else 0) |
        (SECURITY_CONDITION_SECURE_MESSAGING if secure_messaging else 0) |
        (SECURITY_CONDITION_EXTERNAL_AUTHENTICATION if external_authentication else 0) |
        (SECURITY_CONDITION_USER_AUTHENTICATION if user_authentication else 0) |
        security_environment_id
    )

class FileSecurityEnvironmentTemplateElementaryFileId(FileIdentifier):
    identifier = 0x0d

class FileChannelSecurity(TypeContextSimpleBase):
    identifier = 0x0e

    EXCLUSIVE = 0x01
    SECURED = 0x02
    USER_AUTHENTICATED = 0x04

    @classmethod
    def encode(cls, value, codec):
        return value.to_bytes(1, 'big')

    @classmethod
    def decode(cls, value, codec):
        if len(value) != 1:
            raise ValueError
        return int.from_bytes(value, 'big')

class FileDataObjectSecurityTemplate(TypeContextCompositeBase):
    identifier = 0x00

    @classmethod
    def iterItemSchema(cls):
        return itertools.cycle([{
                x.asTagTuple(): x
                for x in (
                    FileSecurityProprietary,
                    FileSecurityExpandedFormatReference,
                    FileSecurityCompactFormat,
                    FileChannelSecurity,
                    FileDataObjectSecurityTemplate,
                    FileDataObjectSecurityProprietary,
                    FileSecurityTemplateExpandedFormat,
                )
        }])

class FileDataObjectSecurityProprietary(NotImplementedBase, TypeContextCompositeBase): #pylint: disable=abstract-method
    identifier = 0x01

class FileShortIdentifierToFileReferenceMapping(NotImplementedBase, TypeContextCompositeBase): #pylint: disable=abstract-method
    identifier  = 0x02
    # list of pairs of (FileIdentifier, FileReference with length > 2)

class FileProprietaryInformationComposite(NotImplementedBase, TypeContextCompositeBase): #pylint: disable=abstract-method
    identifier = 0x05

class SecurityConditionDataObjectList(TypeContextCompositeBase):
    min_length = 1

    @classmethod
    def iterItemSchema(cls):
        return itertools.cycle([{
            x.asTagTuple(): x
            for x in (
                cls.Always,
                cls.Never,
                cls.Byte,
                cls.AuthenticationTemplate,
                cls.ChecksumTemplate,
                cls.SignatureTemplate,
                cls.ConfidentialityTemplate,
                cls.Or,
                cls.Not,
                cls.And,
            )
        }])

    class Always(TypeContextSimpleBase):
        identifier = 0x10

        @classmethod
        def encode(cls, codec):
            return super().encode(b'', codec)

        @classmethod
        def decode(cls, value, codec):
            if value:
                raise ValueError

    class Never(TypeContextSimpleBase):
        identifier = 0x17

        @classmethod
        def encode(cls, codec):
            return super().encode(b'', codec)

        @classmethod
        def decode(cls, value, codec):
            if value:
                raise ValueError

    class Byte(TypeContextSimpleBase):
        identifier = 0x1e

        @classmethod
        def encode(cls, value, codec):
            return value.to_bytes(1, 'big')

        @classmethod
        def decode(cls, value, codec):
            if len(value) != 1:
                raise ValueError
            return int.from_bytes(value, 'big')

    class AuthenticationTemplate(NotImplementedBase, TypeContextCompositeBase): #pylint: disable=abstract-method
        identifier = 0x04

    class ChecksumTemplate(NotImplementedBase, TypeContextCompositeBase): #pylint: disable=abstract-method
        identifier = 0x14

    class SignatureTemplate(NotImplementedBase, TypeContextCompositeBase): #pylint: disable=abstract-method
        identifier = 0x16

    class ConfidentialityTemplate(NotImplementedBase, TypeContextCompositeBase): #pylint: disable=abstract-method
        identifier = 0x18

SecurityConditionDataObjectList.Or  = type('Or',  (SecurityConditionDataObjectList, ), {'identifier': 0x00})
SecurityConditionDataObjectList.Not = type('Not', (SecurityConditionDataObjectList, ), {'identifier': 0x07})
SecurityConditionDataObjectList.And = type('And', (SecurityConditionDataObjectList, ), {'identifier': 0x0f})

class FileSecurityTemplateExpandedFormat(SecurityConditionDataObjectList):
    identifier = 0x0b
    min_length = 2

    @classmethod
    def iterItemSchema(cls):
        return itertools.chain(
            [
                {
                    x.asTagTuple(): x
                    for x in (
                        cls.AccessModeByte,
                        cls.AccessModeCommandHeaderParameter2,
                        cls.AccessModeCommandHeaderParameter1,
                        cls.AccessModeCommandHeaderParameter1Parameter2,
                        cls.AccessModeCommandHeaderInstruction,
                        cls.AccessModeCommandHeaderInstructionParameter2,
                        cls.AccessModeCommandHeaderInstructionParameter1,
                        cls.AccessModeCommandHeaderInstructionParameter1Parameter2,
                        cls.AccessModeCommandHeaderClass,
                        cls.AccessModeCommandHeaderClassParameter2,
                        cls.AccessModeCommandHeaderClassParameter1,
                        cls.AccessModeCommandHeaderClassParameter1Parameter2,
                        cls.AccessModeCommandHeaderClassInstruction,
                        cls.AccessModeCommandHeaderClassInstructionParameter2,
                        cls.AccessModeCommandHeaderClassInstructionParameter1,
                        cls.AccessModeCommandHeaderClassInstructionParameter1Parameter2,
                        cls.AccessModeProprietaryStateMachineTemplate,
                    )
                }
            ],
            super().iterItemSchema(),
        )

    class AccessModeByte(TypeContextSimpleBase):
        identifier = 0x00

        @classmethod
        def encode(cls, value, codec):
            return value.to_bytes(1, 'big')

        @classmethod
        def decode(cls, value, codec):
            if len(value) != 1:
                raise ValueError
            return int.from_bytes(value, 'big')

    class _AccessModeCommandHeaderBase(TypeContextSimpleBase):
        @classmethod
        def encode(cls, apdu_head, codec):
            result = []
            if cls.identifier & 0x08:
                result.append(apdu_head.klass & 0xfc)
            if cls.identifier & 0x04:
                result.append(apdu_head.instruction & 0xfe)
            if cls.identifier & 0x02:
                result.append(apdu_head.parameter1)
            if cls.identifier & 0x01:
                result.append(apdu_head.parameter2)
            return bytes(result)

        @classmethod
        def decode(cls, value, codec):
            data_iter = iter(value)
            return {
                'klass':       (next(data_iter) if cls.identifier & 0x08 else None),
                'instruction': (next(data_iter) if cls.identifier & 0x04 else None),
                'parameter1':  (next(data_iter) if cls.identifier & 0x02 else None),
                'parameter2':  (next(data_iter) if cls.identifier & 0x01 else None),
            }

    class AccessModeCommandHeaderParameter2(_AccessModeCommandHeaderBase):
        identifier = 0x01

    class AccessModeCommandHeaderParameter1(_AccessModeCommandHeaderBase):
        identifier = 0x02

    class AccessModeCommandHeaderParameter1Parameter2(_AccessModeCommandHeaderBase):
        identifier = 0x03

    class AccessModeCommandHeaderInstruction(_AccessModeCommandHeaderBase):
        identifier = 0x04

    class AccessModeCommandHeaderInstructionParameter2(_AccessModeCommandHeaderBase):
        identifier = 0x05

    class AccessModeCommandHeaderInstructionParameter1(_AccessModeCommandHeaderBase):
        identifier = 0x06

    class AccessModeCommandHeaderInstructionParameter1Parameter2(_AccessModeCommandHeaderBase):
        identifier = 0x07

    class AccessModeCommandHeaderClass(_AccessModeCommandHeaderBase):
        identifier = 0x08

    class AccessModeCommandHeaderClassParameter2(_AccessModeCommandHeaderBase):
        identifier = 0x09

    class AccessModeCommandHeaderClassParameter1(_AccessModeCommandHeaderBase):
        identifier = 0x0a

    class AccessModeCommandHeaderClassParameter1Parameter2(_AccessModeCommandHeaderBase):
        identifier = 0x0b

    class AccessModeCommandHeaderClassInstruction(_AccessModeCommandHeaderBase):
        identifier = 0x0c

    class AccessModeCommandHeaderClassInstructionParameter2(_AccessModeCommandHeaderBase):
        identifier = 0x0d

    class AccessModeCommandHeaderClassInstructionParameter1(_AccessModeCommandHeaderBase):
        identifier = 0x0e

    class AccessModeCommandHeaderClassInstructionParameter1Parameter2(_AccessModeCommandHeaderBase):
        identifier = 0x0f

    class AccessModeProprietaryStateMachineTemplate(NotImplementedBase, TypeContextCompositeBase): #pylint: disable=abstract-method
        identifier = 0x1c

class FileCryptographicIdentifierTemplate(NotImplementedBase, TypeContextCompositeBase): #pylint: disable=abstract-method
    identifier = 0x0c

class CryptographicIdentifierTemplate(TypeContextCompositeBase):
    identifier = 0x0c
    min_length = 2

    @classmethod
    def iterItemSchema(cls):
        return itertools.chain(
            [
                {
                    CryptographicMechanismReference.asTagTuple(): CryptographicMechanismReference,
                },
            ],
            itertools.cycle([{
                ObjectIdentifier.asTagTuple(): ObjectIdentifier,
            }]),
        )

class CryptographicMechanismReference(NotImplementedBase, TypeContextSimpleBase): #pylint: disable=abstract-method
    identifier = 0x00
