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

import weakref

# Yet another ASN.1 encoder/decoder with schema support. Sigh.
# pypi asn1: nice and simple, but hard to extend to more tag types
#   ("if tag1 elif tag2 elif tag3 ...")
# pypi pyasn1: many more features, but hard to extend to more serialisation
#   schemes: Implementing compact decoding alone requires copying >200 lines
#   worth of logic from the BER decoder, despite differing trivially from
#   BER. Implementing compact encoding seems to require reimplementing all
#   encoders and linking them to every (generic) tag type. No way.
#   Also, it has surprising encoding definitions (OctetString having a default
#   iso-8859-1 encoding ?).
# Limitations of this implementation: probably many, I'm not too knowledgeable
# in ASN.1 . The ones I know:
# - serialised form is binary (ex: not XML)
# - assumes small values (no consideration for memory usage)
# Which should not matter for smartcard-type workloads anyway.

# Schema structure:
# mapping tag tuple -> TagBase subclass
# TagBase -> iterator -> mapping tag tuple -> TagBase of content for item 0
#                     -> mapping tag tuple -> TagBase of content for item 1
# ...

# TagBase [
#   { # Possible tags in first position
#     tag: TagBase
#     ...
#   },
#   ...
# ]
#
# infinite repetition: itertools.cycle

# TODO: get rid of many explicit asTagTuple calls when defining schemas.
# idea: a dict type initialised with just a list of tag classes, itself calling
# asTagTuple when constructed.

# Note: these values are stored in ZODB, so Enum would add a non-trivial
# overhead.

CLASS_UNIVERSAL = 0
CLASS_APPLICATION = 1
CLASS_CONTEXT = 2
CLASS_PRIVATE = 3

_CLASS_NAME_DICT = {
    CLASS_UNIVERSAL: 'Universal',
    CLASS_APPLICATION: 'Application',
    CLASS_CONTEXT: 'Context',
    CLASS_PRIVATE: 'Private',
}

class MetaTag(type):
    def __eq__(cls, other):
        return (
            isinstance(other, MetaTag) and
            cls.asTagTuple() == other.asTagTuple()
        )

    def __hash__(cls):
        return hash(cls.asTagTuple())

class TypeBase(metaclass=MetaTag):
    klass = None
    is_composite = None
    identifier = None

    @classmethod
    def asTagTuple(cls):
        return (cls.klass, cls.is_composite, cls.identifier)

    @classmethod
    def encode(cls, value, codec):
        """
        Convert value (python native object) into bytes.
        """
        raise NotImplementedError(repr(cls))

    @classmethod
    def decode(cls, value, codec):
        """
        Convert value (bytes) into a python object.
        """
        raise NotImplementedError(repr(cls))

class TypeListBase(TypeBase):
    is_composite = True
    min_length = None
    max_length = None

    @classmethod
    def iterItemSchema(cls):
        raise NotImplementedError(repr(cls))

    @classmethod
    def encode(cls, value, codec):
        if cls.max_length is not None and len(value) > cls.max_length:
            raise ValueError('Too many items: %r' % len(value))
        if cls.min_length is not None and len(value) < cls.min_length:
            raise ValueError('Too few items: %r' % len(value))
        result = []
        for (value_tag, value_value), schema in zip(value, cls.iterItemSchema()):
            if value_tag.asTagTuple() not in schema:
                raise ValueError('Unexpected tag %r, schema: %r' % (value_tag, schema))
            result.append(codec.encode(tag=value_tag, value=value_value))
        return b''.join(result)

    @classmethod
    def decode(cls, value, codec):
        result = []
        for schema in cls.iterItemSchema():
            if not value:
                if cls.min_length is not None and len(result) < cls.min_length:
                    raise ValueError('Not enough data: parsed=%r' % (result, ))
                break
            item_tag, item_value, value = codec.decode(value, schema=schema)
            result.append((item_tag, item_value))
            if value and cls.max_length is not None and len(result) >= cls.max_length:
                raise ValueError('Too much data: parsed=%r, remain=%r' % (result, value))
        return result

#
#   Universal tags
#

class TypeUniveralBase(TypeBase): #pylint: disable=abstract-method
    klass = CLASS_UNIVERSAL

class TypeUniveralSimpleBase(TypeUniveralBase): #pylint: disable=abstract-method
    is_composite = False

class TypeUniversalCompositeBase(TypeListBase): #pylint: disable=abstract-method
    klass = CLASS_UNIVERSAL

class Boolean(TypeUniveralSimpleBase):
    identifier = 0x01

    @classmethod
    def encode(cls, value, codec):
        return bool(value).to_bytes(1, 'big')

    @classmethod
    def decode(cls, value, codec):
        if value not in (b'\x00', b'\x01'):
            raise ValueError(value.hex())
        return bool.from_bytes(value)

class IntegerBase(TypeBase):
    is_composite = False

    @classmethod
    def encode(cls, value, codec):
        length, remainder = divmod(value.bit_length(), 8)
        return value.to_bytes(
            length + (1 if remainder else 0),
            'big',
        )

    @classmethod
    def decode(cls, value, codec):
        return int.from_bytes(value, 'big')

class Integer(TypeUniveralSimpleBase, IntegerBase):
    """
    Big endian integer of any length.
    """
    identifier = 0x02

class OctetStringBase(TypeBase):
    is_composite = False

    @classmethod
    def encode(cls, value, codec):
        return value

    @classmethod
    def decode(cls, value, codec):
        return value

class OctetString(TypeUniveralSimpleBase, OctetStringBase):
    identifier = 0x04

class Null(TypeUniveralSimpleBase):
    identifier = 0x05

    @classmethod
    def encode(cls, value, codec):
        if value is not None:
            raise ValueError(repr(value))
        return b''

    @classmethod
    def decode(cls, value, codec):
        if value != b'':
            raise ValueError(value.hex())

class ObjectIdentifier(TypeUniveralSimpleBase):
    identifier = 0x06

    @classmethod
    def encode(cls, value, codec):
        iter_oid = (int(x, 10) for x in value.split('.'))
        first = next(iter_oid)
        second = next(iter_oid)
        if second >= 40:
            raise ValueError
        result = [
            first * 40 + second,
        ]
        for entry in iter_oid:
            entry_result = []
            while entry > 0x7f:
                entry_result.append(entry & 0x7f)
                entry >>= 7
            entry_result.append(entry)
            result.extend((x | 0x80 for x in reversed(entry_result[1:])))
            result.append(entry_result[0])
        return b''.join(x.to_bytes(1, 'big') for x in result)

    @classmethod
    def decode(cls, value, codec):
        result = list(divmod(value[0], 40))
        current = 0
        for item in value[1:]:
            if item & 0x80:
                current = (current | (item & 0x7f)) << 7
            else:
                result.append(current | item)
                current = 0
        if current:
            raise ValueError(value.hex())
        return '.'.join('%i' % x for x in result)

class Enumerated(Integer):
    identifier = 0x0a

    def __init__(self, int_python_pair_list):
        """
            List of integer and whatever-hashable-python-object pairs defining
            the enumeration.
        """
        self.__int_python_dict = dict(int_python_pair_list)
        self.__python_int_dict = {
            value: key
            for key, value in int_python_pair_list
        }
        if len(self.__int_python_dict) != len(self.__python_int_dict):
            raise ValueError

    def encode(self, value, codec):
        return super().encode(value=self.__python_int_dict[value], codec=codec)

    def decode(self, value, codec):
        return self.__int_python_dict[super().decode(value=value, codec=codec)]

class Sequence(TypeUniversalCompositeBase): #pylint: disable=abstract-method
    identifier = 0x10

    # Still abstract, implement iterItemSchema to make concrete.

class Set(TypeUniversalCompositeBase): #pylint: disable=abstract-method
    identifier = 0x11

    # Still abstract, implement iterItemSchema to make concrete.

#
#   Codecs
#

class CodecBase:
    @classmethod
    def encode(cls, tag, value):
        """
        Encode value (python object) using tag rules.
        Returns the encoded value (bytes).
        """
        return cls.wrapValue(
            tag=tag,
            encoded=tag.encode(value=value, codec=cls),
        )

    @classmethod
    def encodeTag(cls, tag):
        """
        Encode given tag.
        """
        raise NotImplementedError

    @classmethod
    def wrapValue(cls, tag, encoded):
        """
        Encode given tag with given value as payload.
        No type checking.
        """
        return cls.encodeTagLength(tag=tag, length=len(encoded)) + encoded

    @classmethod
    def encodeTagLength(cls, tag, length):
        """
        Encode given tag and length.
        """
        raise NotImplementedError

    @classmethod
    def decode(cls, value, schema):
        """
        Decode value (bytes) into an element from schema.
        Returns the tag, decoded content, and any remaining bytes.
        """
        tag_tuple, length_and_payload = cls.decodeTag(
            value=value,
        )
        length, payload = cls.decodeLength(value=length_and_payload)
        tag = schema[tag_tuple]
        return (
            tag,
        ) + cls._decode(
            tag=tag,
            length=length,
            payload=payload,
        )

    @classmethod
    def _decode(cls, tag, length, payload):
        chunk = payload[:length]
        if len(chunk) != length:
            raise ValueError('expected %i bytes, got %i' % (length, len(chunk)))
        return (
            tag.decode(
                value=chunk,
                codec=cls,
            ),
            payload[length:],
        )

    @classmethod
    def iterDecode(cls, value, schema):
        """
        Decode concatenated values.
        """
        while value:
            tag_tuple, length_and_payload = cls.decodeTag(
                value=value,
            )
            tag = schema[tag_tuple]
            length, payload = cls.decodeLength(value=length_and_payload)
            item, value = cls._decode(
                tag=tag,
                length=length,
                payload=payload,
            )
            yield tag, item

    @classmethod
    def iterDecodeTag(cls, value, schema):
        """
        Decode concatenated tags.
        """
        while value:
            tag_tuple, value = cls.decodeTag(value=value)
            yield schema[tag_tuple]

    @classmethod
    def iterDecodeTagLength(cls, value, schema):
        """
        Decode concatenated tags and lengths.
        """
        while value:
            (klass, is_composite, identifier), value = cls.decodeTag(value=value)
            length, value = cls.decodeLength(value=value)
            yield (
                schema[(
                    klass,
                    is_composite,
                    identifier,
                )],
                length,
            )

    @classmethod
    def decodeTag(cls, value):
        """
        From given value, extract the class, composition and identifier, and
        return bytes following the tag (containing the length and payload).
        """
        raise NotImplementedError

    @classmethod
    def decodeLength(cls, value):
        """
        From given value, extract the length and return bytes following the
        length (containing the payload).
        """
        raise NotImplementedError

class CodecCompact(CodecBase):
    """
    4 bits tag identifier (class universal, non-composite)
    4 bits length
    data
    """
    @classmethod
    def encodeTag(cls, tag):
        assert tag.klass == CLASS_UNIVERSAL, repr(tag)
        assert tag.is_composite is False, repr(tag)
        assert tag.identifier is not None, repr(tag)
        if (
            tag.klass != CLASS_UNIVERSAL or
            tag.is_composite
        ):
            raise ValueError
        return (tag.identifier << 4).to_bytes(1, 'big')

    @classmethod
    def encodeTagLength(cls, tag, length):
        if (
            tag.klass != CLASS_UNIVERSAL or
            tag.is_composite or
            length > 0xf
        ):
            raise ValueError
        return (
            (tag.identifier << 4) | length
        ).to_bytes(1, 'big')

    @classmethod
    def decodeTag(cls, value):
        return (
            (
                CLASS_UNIVERSAL,
                False,
                value[0] >> 4,
            ),
            value,
        )

    @classmethod
    def decodeLength(cls, value):
        return (
            value[0] & 0xf,
            value[1:],
        )

class CodecSimple(CodecBase):
    """
    2 bits class
    1 bit composite flag
    5 bits identifier
    1 or 3 bytes length (0..64kB)
    data
    """
    @classmethod
    def encodeTag(cls, tag):
        assert tag.klass in _CLASS_NAME_DICT, repr(tag)
        assert tag.is_composite is True or tag.is_composite is False, repr(tag)
        assert tag.identifier is not None, repr(tag)
        if tag.identifier > 0x1f:
            raise ValueError
        return (
            (tag.klass << 6) |
            (0x20 if tag.is_composite else 0) |
            tag.identifier
        ).to_bytes(1, 'big')

    @classmethod
    def encodeTagLength(cls, tag, length):
        return cls.encodeTag(tag) + (
            length.to_bytes(1, 'big')
            if length < 0xff else
            b'\xff' + length.to_bytes(2, 'big')
        )

    @classmethod
    def decodeTag(cls, value):
        return (
            (
                value[0] >> 6,
                bool(value[0] & 0x20),
                value[0] & 0x1f,
            ),
            value[1:],
        )

    @classmethod
    def decodeLength(cls, value):
        if value[0] == b'\xff':
            length = int.from_bytes(value[1:3], 'big')
            offset = 3
        else:
            length = value[0]
            offset = 1
        return (
            length,
            value[offset:],
        )

class CodecBER(CodecBase):
    """
    2 bits class
    1 bit composite flag
    5 to 21 bits identifier (0..16k)
    1 to 5 bytes length (0..4GB)
    data
    """
    @classmethod
    def encodeTag(cls, tag):
        assert tag.klass in _CLASS_NAME_DICT, repr(tag)
        assert tag.is_composite is True or tag.is_composite is False, repr(tag)
        assert tag.identifier is not None, repr(tag)
        encoded_head = (
            (tag.klass << 6) |
            (0x20 if tag.is_composite else 0) |
            min(tag.identifier, 0x1f)
        ).to_bytes(1, 'big')
        if tag.identifier >= 0x1f:
            if tag.identifier < 0x80:
                encoded_head += tag.identifier.to_bytes(1, 'big')
            elif tag.identifier < 0x4000:
                encoded_head += (
                    (0x80 | (tag.identifier >> 7)).to_bytes(1, 'big') +
                    (tag.identifier & 0x7f).to_bytes(1, 'big')
                )
            else:
                raise ValueError
        return encoded_head

    @classmethod
    def encodeTagLength(cls, tag, length):
        if length < 0x80:
            encoded_length = length.to_bytes(1, 'big')
        else:
            encoded_len = length.to_bytes(4, 'big').lstrip(b'\x00')
            encoded_length = (0x80 + len(encoded_len)).to_bytes(1, 'big') + encoded_len
        return cls.encodeTag(tag=tag) + encoded_length

    @classmethod
    def decodeTag(cls, value):
        identifier = value[0] & 0x1f
        if identifier == 0x1f:
            if value[1] & 0x80:
                if value[2] & 0x80:
                    raise ValueError
                identifier = ((value[1] & 0x7f) << 7) | value[2]
                offset = 3
            else:
                identifier = (value[1] & 0x7f)
                offset = 2
        else:
            offset = 1
        return (
            (
                value[0] >> 6,
                bool(value[0] & 0x20),
                identifier,
            ),
            value[offset:],
        )

    @classmethod
    def decodeLength(cls, value):
        length = value[0]
        offset = 1
        if length & 0x80:
            length_length = length & 0x7f
            if length_length > 4:
                raise ValueError
            length = int.from_bytes(
                value[offset:offset + length_length],
                'big',
            )
            offset += length_length
        return (
            length,
            value[offset:],
        )

#
#   Schema helpers
#

class _AllSchema:
    __cache = weakref.WeakValueDictionary()
    def __getitem__(self, tag_properties):
        try:
            return self.__cache[tag_properties]
        except KeyError:
            klass, is_composite, identifier = tag_properties
            result = self.__cache[tag_properties] = type(
                'Tag' + _CLASS_NAME_DICT[klass] + (
                    'Composite'
                    if is_composite else
                    'Simple'
                ) + hex(identifier),
                (TypeBase, ),
                {
                    'klass': klass,
                    'is_composite': is_composite,
                    'identifier': identifier,
                },
            )
            return result
AllSchema = _AllSchema()

assert ObjectIdentifier.encode('1.3.36.3.2.1', codec=CodecBER) == b'\x2b\x24\x03\x02\x01'
assert ObjectIdentifier.encode('1.3.14.3.2.26', codec=CodecBER) == b'\x2b\x0e\x03\x02\x1a'
assert ObjectIdentifier.encode('2.16.840.1.101.3.4.2.4', codec=CodecBER) == b'\x60\x86\x48\x01\x65\x03\x04\x02\x04'
assert ObjectIdentifier.encode('2.16.840.1.101.3.4.2.1', codec=CodecBER) == b'\x60\x86\x48\x01\x65\x03\x04\x02\x01'
assert ObjectIdentifier.encode('2.16.840.1.101.3.4.2.2', codec=CodecBER) == b'\x60\x86\x48\x01\x65\x03\x04\x02\x02'
assert ObjectIdentifier.encode('2.16.840.1.101.3.4.2.3', codec=CodecBER) == b'\x60\x86\x48\x01\x65\x03\x04\x02\x03'
assert ObjectIdentifier.decode(b'\x2b\x24\x03\x02\x01', codec=CodecBER) == '1.3.36.3.2.1'
assert ObjectIdentifier.decode(b'\x2b\x0e\x03\x02\x1a', codec=CodecBER) == '1.3.14.3.2.26'
assert ObjectIdentifier.decode(b'\x60\x86\x48\x01\x65\x03\x04\x02\x04', codec=CodecBER) == '2.16.840.1.101.3.4.2.4'
assert ObjectIdentifier.decode(b'\x60\x86\x48\x01\x65\x03\x04\x02\x01', codec=CodecBER) == '2.16.840.1.101.3.4.2.1'
assert ObjectIdentifier.decode(b'\x60\x86\x48\x01\x65\x03\x04\x02\x02', codec=CodecBER) == '2.16.840.1.101.3.4.2.2'
assert ObjectIdentifier.decode(b'\x60\x86\x48\x01\x65\x03\x04\x02\x03', codec=CodecBER) == '2.16.840.1.101.3.4.2.3'
