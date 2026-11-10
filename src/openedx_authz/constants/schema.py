"""Shared constants for the static authorization schema (ADR 0023/0025).

This is the single source of truth for the ``base`` / ``extension`` origin
values. ``SchemaOriginKind`` is a plain ``str`` enum with no Django or Casbin
dependency, so both the engine schema types
(``openedx_authz.engine.schema.types``) and the Django models layer
(``openedx_authz.models.schema.OriginKind``) can share the same values without
either layer depending on the other.
"""

from __future__ import annotations

from enum import Enum
from types import MappingProxyType

AUTHZ_JSON_SCHEMA_SETTING = "OPENEDX_AUTHZ_JSON_SCHEMA"

AUTHZ_JSON_SCHEMA_V1_0 = "openedx_authz.engine.schema/authz-schema-v1.json"
AUTHZ_JSON_SCHEMA_V1_1 = "openedx_authz.engine.schema/authz-schema-v1.1.json"

# The JSON Schema that validates each supported ``schema_version`` (ADR 0034 §2). Each file is
# validated against the JSON Schema of the version it declares, so files of different versions
# can be loaded together.
DEFAULT_AUTHZ_JSON_SCHEMA = MappingProxyType(
    {
        "1.0": AUTHZ_JSON_SCHEMA_V1_0,
        "1.1": AUTHZ_JSON_SCHEMA_V1_1,
    }
)


class SchemaOriginKind(str, Enum):
    """Whether a schema contribution is a base definition or an extension.

    ``BASE`` comes from a role's own definition; ``EXTENSION`` is added by a
    ``role_extensions`` entry (ADR 0023/0025). Subclassing ``str`` keeps the
    members interchangeable with their raw string values, which is why the
    persistence layer can store them directly.
    """

    BASE = "base"
    EXTENSION = "extension"
