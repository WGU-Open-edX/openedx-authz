"""Validate parsed schema values against the configured JSON Schemas.

The schemas own supported ``schema_version`` values, required fields,
identifier and permission-reference formats, scope formats, collection shapes,
value types, and Paragon icon-name format. Semantic relationship and icon
membership checks remain in :mod:`.validation`.

Each document is validated against the JSON Schema of the ``schema_version`` it
declares (ADR 0034 §2), so documents of different supported versions can be
validated together.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from importlib import resources

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from jsonschema import Draft202012Validator

from openedx_authz.constants.schema import AUTHZ_JSON_SCHEMA_SETTING, DEFAULT_AUTHZ_JSON_SCHEMA
from openedx_authz.engine.schema.issues import IssueLevel, ValidationIssue
from openedx_authz.engine.schema.types import ParsedSchemaDocument


def document_validator(schema_resource: str) -> Draft202012Validator:
    """Load an authorization validator from a package resource."""
    schema_package, separator, schema_filename = schema_resource.partition("/")
    if not separator:
        raise ValueError(f"{AUTHZ_JSON_SCHEMA_SETTING} must be a package-anchored resource path.")
    schema_path = resources.files(schema_package).joinpath(schema_filename)
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema)


def configured_schema_resources() -> Mapping[str, str]:
    """Return the configured ``schema_version`` to JSON Schema resource mapping, including outside Django.

    Raises:
        ImproperlyConfigured: If the setting is not a non-empty mapping, for example the single
            resource string accepted before schema version 1.1.
    """
    try:
        configured = getattr(settings, AUTHZ_JSON_SCHEMA_SETTING, DEFAULT_AUTHZ_JSON_SCHEMA)
    except ImproperlyConfigured:
        return DEFAULT_AUTHZ_JSON_SCHEMA
    if not isinstance(configured, Mapping) or not configured:
        raise ImproperlyConfigured(
            f"{AUTHZ_JSON_SCHEMA_SETTING} must map each schema_version to a package-anchored JSON Schema "
            f'resource, for example {{"1.0": "{DEFAULT_AUTHZ_JSON_SCHEMA["1.0"]}", '
            f'"1.1": "{DEFAULT_AUTHZ_JSON_SCHEMA["1.1"]}"}}. Got {configured!r}.'
        )
    return configured


def _version_key(version: str) -> tuple[int, ...]:
    """Order ``major.minor`` versions numerically, so ``"1.10"`` sorts after ``"1.9"``."""
    try:
        return tuple(int(part) for part in version.split("."))
    except (AttributeError, ValueError) as exc:
        raise ImproperlyConfigured(
            f"{AUTHZ_JSON_SCHEMA_SETTING} keys must be 'major.minor' schema versions, got {version!r}."
        ) from exc


class SchemaSyntaxValidator:
    """Collect JSON Schema findings for parsed documents."""

    def validate(self, documents: list[ParsedSchemaDocument]) -> list[ValidationIssue]:
        """Return every structural error from every parsed document."""
        validators = {
            version: document_validator(resource)
            for version, resource in sorted(
                configured_schema_resources().items(), key=lambda item: _version_key(item[0])
            )
        }
        latest = next(reversed(validators.values()))

        issues = []
        for document in documents:
            data = document.data
            if not isinstance(data, dict) or "schema_version" not in data:
                # Without a version to select by, the latest schema reports the missing field or
                # the wrong root type, along with any other structural error.
                issues.extend(self._errors(latest, document))
                continue

            version = data["schema_version"]
            validator = validators.get(version) if isinstance(version, str) else None
            if validator is None:
                issues.append(self._unsupported_version(version, validators, document))
                continue
            issues.extend(self._errors(validator, document))
        return issues

    @staticmethod
    def _errors(validator: Draft202012Validator, document: ParsedSchemaDocument) -> list[ValidationIssue]:
        """Return the JSON Schema errors of one document as validation issues."""
        return [
            ValidationIssue(IssueLevel.ERROR, f"{error.json_path}: {error.message}", document.source.source_id)
            for error in validator.iter_errors(document.data)
        ]

    @staticmethod
    def _unsupported_version(version: object, validators: dict, document: ParsedSchemaDocument) -> ValidationIssue:
        """Report a ``schema_version`` with no configured JSON Schema.

        The rest of the document is not checked, because its fields depend on the version.
        """
        supported = ", ".join(repr(supported_version) for supported_version in validators)
        message = f"$.schema_version: {version!r} is not a supported schema version. Supported versions: {supported}."
        if not isinstance(version, str):
            message += " Quote the value in YAML so it remains a string."
        return ValidationIssue(IssueLevel.ERROR, message, document.source.source_id)
