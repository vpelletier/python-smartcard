# Copyright (C) 2018-2020  Vincent Pelletier <plr.vincent@gmail.com>
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
from functools import partial
import itertools
import weakref
import persistent
import transaction

def bitpos(value): # pylint: disable=inconsistent-return-statements
    """
    Return the position of the (only) bit set in given value.
    """
    # Must have at least one bit set
    assert value
    for result in itertools.count():
        if value & 1:
            # Must have exactly one bit set
            assert not value ^ 1
            return result
        value >>= 1

def bitcount(value):
    """
    Return the number of bits set in given value.
    """
    result = 0
    while value:
        result += value & 1
        value >>= 1
    return result

transaction_manager = transaction.TransactionManager(
    explicit=True,
)

def _this_is_a_trap():
    """
    Persistence cannot serialise functions.
    """

class Antipersistent:
    """
    Prevent instances from being persisted, to detect bugs.
    Inherit from Persistent so that __getstate__ is called on commit.
    """
    def __init__(self, *args, **kw):
        super().__init__(*args, **kw)
        self.__it_s_a_trap = _this_is_a_trap

class DefaultWeakKeyDictionary(weakref.WeakKeyDictionary):
    def __init__(self, func):
        self.__value_ctor = func
        super().__init__()

    def __getitem__(self, key):
        try:
            return super().__getitem__(key)
        except KeyError:
            result = self[key] = self.__value_ctor()
            return result

class VolatileSurvivorContainer:
    pass

class PersistentWithVolatileSurvivor(persistent.Persistent):
    """
    persistent.Persistent with an extra twist: attributes named _v_s_* survive
    object ghostification, and instead follow the lifetime of the "live" python
    object.
    """
    __volatile_survivor_dict = DefaultWeakKeyDictionary(
        VolatileSurvivorContainer,
    )

    def setupVolatileSurvivors(self):
        pass

    def __setstate__(self, state):
        super().__setstate__(state)
        self.setupVolatileSurvivors()

    def __getattr__(self, name):
        if name.startswith('_v_s_'):
            return getattr(self.__volatile_survivor_dict[self], name)
        raise AttributeError(name)

    def __setattr__(self, name, value):
        if name.startswith('_v_s_'):
            setattr(self.__volatile_survivor_dict[self], name, value)
        super().__setattr__(name, value)

    def __delattr__(self, name):
        if name.startswith('_v_s_'):
            delattr(self.__volatile_survivor_dict[self], name)
        super().__delattr__(name)

def chainBytearrayList(bytearray_list):
    if len(bytearray_list) == 1:
        return bytearray_list[0]
    # TODO: make a class to not have to copy memory
    result = bytearray(sum(len(x) for x in bytearray_list))
    base = 0
    for chunk in bytearray_list:
        old_base = base
        base += len(chunk)
        result[old_base:base] = chunk
    return result

class NamedSingleton:
    def __init__(self, caption):
        self.__caption = caption

    def __repr__(self):
        return '<%s(%r) at %x>' % (
            self.__class__.__name__,
            self.__caption,
            id(self),
        )
