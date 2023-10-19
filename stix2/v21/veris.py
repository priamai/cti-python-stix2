"""STIX 2.1 Veris objects.

Embedded observable object types, such as Email MIME Component, which is
embedded in Email Message objects, inherit from ``_STIXBase21`` instead of
_Observable and do not have a ``_type`` attribute.
"""

from collections import OrderedDict
import itertools

from ..custom import _custom_observable_builder
from ..exceptions import AtLeastOnePropertyError, DependentPropertiesError
from ..properties import (
    BinaryProperty, BooleanProperty, DictionaryProperty,
    EmbeddedObjectProperty, EnumProperty, ExtensionsProperty, FloatProperty,
    HashesProperty, HexProperty, IDProperty, IntegerProperty, ListProperty,
    OpenVocabProperty, ReferenceProperty, StringProperty, TimestampProperty,
    TypeProperty,
)
from .base import _Extension, _Observable, _STIXBase21
from .common import CustomExtension, GranularMarking
from .vocab import (
    ACCOUNT_TYPE, ENCRYPTION_ALGORITHM, HASHING_ALGORITHM,
    NETWORK_SOCKET_ADDRESS_FAMILY, NETWORK_SOCKET_TYPE,
    WINDOWS_INTEGRITY_LEVEL, WINDOWS_PEBINARY_TYPE, WINDOWS_REGISTRY_DATATYPE,
    WINDOWS_SERVICE_START_TYPE, WINDOWS_SERVICE_STATUS, WINDOWS_SERVICE_TYPE,
)


class Asset(_Observable):
    """For more detailed information on this object's properties, see
    `the Veris specification <https://verisframework.org/assets.html>`__.
    """

    _type = 'veris-asset'
    _properties = OrderedDict([
        ('type', TypeProperty(_type, spec_version='2.1')),
        ('spec_version', StringProperty(fixed='2.1')),
        ('id', IDProperty(_type, spec_version='2.1')),
        ('value', StringProperty(required=True)),
        ('variety', StringProperty(required=False)),
        ('ownership', StringProperty(required=False)),
        ('management', StringProperty(required=False)),
        ('hosting', StringProperty(required=False)),
        ('accessibility', StringProperty(required=False)),
        ('cloud', StringProperty(required=False)),
        ('notes', StringProperty(required=False)),
        ('resolves_to_refs', ListProperty(ReferenceProperty(valid_types=['ipv4-addr', 'ipv6-addr', 'domain-name'], spec_version='2.1'))),
        #('object_marking_refs', ListProperty(ReferenceProperty(valid_types='marking-definition', spec_version='2.1'))),
        #('granular_markings', ListProperty(GranularMarking)),
        ('labels', ListProperty(StringProperty)),
        ('defanged', BooleanProperty(default=lambda: False)),
        ('extensions', ExtensionsProperty(spec_version='2.1')),
    ])
    _id_contributing_properties = ["value"]
