import datetime
import os
import shutil
import string
import subprocess
import sys
import urllib.parse
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import (
    Annotated,
    Any,
    Final,
    Generic,
    Iterable,
    Iterator,
    Literal,
    Sequence,
    Type,
    TypeVar,
    Union,
    get_args,
    TypedDict,
)
import annotated_types
from annotated_types import BaseMetadata, MaxLen, MinLen
from pydantic import (
    AfterValidator,
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    GetCoreSchemaHandler,
    PlainSerializer,
    TypeAdapter,
    ValidationInfo,
    ValidatorFunctionWrapHandler,
    WrapSerializer,
    Base64Encoder,
)
from pydantic_core import CoreSchema, core_schema
from rich import print

NONE_VALUES: Final = {None, "", "_none"}
TRUTHY_VALUES: Final = {True, "1", "yes", "y", "true", "t", "on"}
FALSY_VALUES: Final = {False, "0", "no", "n", "false", "f", "off"}


def strip_whitespace(v: Any) -> Any:
    return v.strip() if isinstance(v, str) else v


def parse_empty_str_as_none(v: Any, info) -> Any:
    print(info)
    return None if v == "" else v


def parse_none_as_empty_str(v: Any) -> Any:
    return "" if v is None else v


def strip_and_parse_empty_str_as_none(v: Any) -> Any:
    if isinstance(v, str):
        v = v.strip()
        lowered = v.lower()
        return None if lowered in NONE_VALUES else v
    return v


Str_strip_as_none = BeforeValidator(strip_and_parse_empty_str_as_none)


@dataclass
class StringConstraints:
    strip_whitespace: bool | None = None
    to_upper: bool | None = None
    to_lower: bool | None = None
    min_length: int | None = None
    max_length: int | None = None
    pattern: Union[dict[str, str], str, None] = None
    multiline: bool | None = None
    forbidden_chars: str | None = None
    empty_str_is_none: bool | None = None

    def __get_pydantic_core_schema__(
        self, source_type: Any, handler: GetCoreSchemaHandler
    ) -> CoreSchema:
        base_schema = handler(source_type)
        str_schema = [
            # Coerce value to string
            base_schema,
            core_schema.str_schema(
                pattern=self.pattern.regexp if self.pattern else None,
                max_length=self.max_length,
                min_length=self.min_length,
                strip_whitespace=self.strip_whitespace,
                to_lower=self.to_lower,
                to_upper=self.to_upper,
            ),
            (
                core_schema.no_info_plain_validator_function(self.assert_not_multiline)
                if self.multiline is False
                else None
            ),
            (
                core_schema.no_info_plain_validator_function(
                    self.assert_no_forbidden_characters
                )
                if self.forbidden_chars
                else None
            ),
        ]

        schema: CoreSchema = core_schema.chain_schema(
            [s for s in str_schema if s is not None]
        )

        if type(None) in get_args(source_type):
            schema = core_schema.nullable_schema(schema)

        if self.empty_str_is_none:
            schema = core_schema.no_info_before_validator_function(
                strip_and_parse_empty_str_as_none, schema
            )

        return schema

    def assert_not_multiline(self, value: str):
        if "\n" in value:
            raise ValueError("Str contain multiline character")

        return value

    def assert_no_forbidden_characters(self, value: str):
        if any(char in value for char in (self.forbidden_chars or "")):
            raise ValueError(f"forbidden characters in string: {self.forbidden_chars}")

        return value


@dataclass
class BoolConstraints:
    serialization: tuple[int, int] | tuple[bool, bool] | tuple[str, str] = (True, False)

    def __get_pydantic_core_schema__(
        self, source_type: Any, handler: GetCoreSchemaHandler
    ) -> CoreSchema:
        base_schema: CoreSchema = core_schema.bool_schema(
            serialization=core_schema.plain_serializer_function_ser_schema(
                self.serialize, when_used="json-unless-none"
            )
        )

        if type(None) in get_args(source_type):  # nullable
            base_schema = core_schema.nullable_schema(base_schema)

        # If serialized's bool is not common bool repr, first parse it.
        if any(
            value not in values
            for value, values in zip(self.serialization, (TRUTHY_VALUES, FALSY_VALUES))
        ):
            return core_schema.no_info_before_validator_function(
                self.parse_custom_bool, base_schema
            )

        return base_schema

    def parse_custom_bool(self, value: int | bool | str):
        if value == self.serialization[0]:
            return True
        elif value == self.serialization[1]:
            return False

        # Let `bool_schema` deal with common errors
        return value

    def serialize(self, value: bool):
        return self.serialization[0] if value is True else self.serialization[1]


@dataclass
class DatetimeConstraints:
    type: Literal["date", "time", "datetime"] = "datetime"
    strftime: str | None = None

    def __get_pydantic_core_schema__(
        self, source_type: Any, handler: GetCoreSchemaHandler
    ) -> CoreSchema:

        # base_schema = getattr(core_schema, f"{self.type}_schema")(
        #     serialization=core_schema.plain_serializer_function_ser_schema(
        #         self.serialize, when_used="json-unless-none"
        #     )
        # )
        base_schema = getattr(core_schema, f"{self.type}_schema")(
            serialization=core_schema.plain_serializer_function_ser_schema(
                self.serialize, when_used="json-unless-none"
            )
        )

        if type(None) in get_args(source_type):  # nullable
            base_schema = core_schema.nullable_schema(base_schema)

        nipv = core_schema.no_info_plain_validator_function
        base_schema = core_schema.chain_schema(
            [
                nipv(strip_and_parse_empty_str_as_none),
                # core_schema.union_schema([
                #     core_schema.float_schema(),
                #     core_schema.int_schema(),
                #     core_schema.str_schema(),
                #     core_schema.none_schema(),
                # ], mode="left_to_right"),
                nipv(self.parse_other_date_format),
                base_schema,
            ]
        )

        return base_schema

    def parse_other_date_format(self, value: str | int | float):
        print("value", value, type(value))
        if isinstance(value, str):
            if value.replace(".", "", 1).replace("-", "", 1).isdigit():
                value = float(value)
            elif self.type != "datetime" and any(v in value for v in " T"):
                # split iso datetime only, `base_schema` should handle the rest
                d, t = value.split("T") if "T" in value else value.split(" ")

                return d if self.type == "date" else t
            else:
                # let `base_schema` check the string validity
                return value

        if isinstance(value, (int, float)):
            value = datetime.datetime.utcfromtimestamp(value)

        if self.type != "datetime" and isinstance(value, datetime.datetime):
            if self.type == "time":
                value = value.time()
            elif self.type == "date":
                value = value.date()

        return value

    def serialize(self, value: datetime.date | datetime.time | datetime.datetime):
        if self.strftime:
            return value.strftime(self.strftime)

        return value.isoformat()


T = TypeVar("T")


@dataclass
class ListConstraints(Generic[T]):
    unique_items: bool = False

    def __get_pydantic_core_schema__(
        self, source_type: Any, handler: GetCoreSchemaHandler
    ) -> CoreSchema:
        args = get_args(source_type)

        if type(None) in args:
            args = get_args(args[0])

        inner_schema = handler.generate_schema(args[0])
        # if args:
        # else:
        #     inner_schema = handler.generate_schema(list[str])
        base_schema = handler(source_type)
        # inner_schema = base_schema["items_schema"]
        base_schema = core_schema.no_info_before_validator_function(
            self.pre_parse,
            base_schema,
            serialization=core_schema.wrap_serializer_function_ser_schema(
                self.serialize,
                schema=core_schema.union_schema([base_schema, inner_schema]),
                return_schema=core_schema.str_schema(),
                when_used="json-unless-none",
            ),
        )

        base_schema = core_schema.with_info_after_validator_function(
            self.validate,
            base_schema,
        )
        print(base_schema, args[0])

        return base_schema

    def pre_parse(self, value: Any) -> Any:
        if isinstance(value, list):
            return None if not len(value) else value

        if isinstance(value, str):
            value = value.strip().strip(",")
            value = strip_and_parse_empty_str_as_none(value)
            if value is None:
                return value
            return [v.strip() for v in value.split(",")]

        return value

    def validate(self, value: list[Any] | None, info) -> list[Any] | None:
        print("validate", info)
        if value is None:
            return value

        if self.unique_items:
            unique_values = set(value)
            if len(unique_values) != len(value):
                raise ValueError("values_not_unique")

        choices = info.context.get("choices") if info.context else None
        if choices:
            # Or use Literal as expected type, or use info.context for apps, etc.
            if any(v not in choices for v in value):
                raise ValueError("not_valid_choice")

        return value

    def serialize(self, value: list[Any], handler) -> str:
        print("list serialize", value)
        return ",".join([str(handler(v)) for v in value])


ApiFile = TypedDict("ApiFile", {"name": str, "content": Base64Encoder})
AnyFile = ApiFile | Path


@dataclass
class FileConstraints:
    _upload_dirs: set[Path] = Field(default_factory=set)

    def __get_pydantic_core_schema__(
        self, source_type: Any, handler: GetCoreSchemaHandler
    ) -> CoreSchema:
        base_schema = handler(source_type)

        return core_schema.no_info_before_validator_function(
            self.parse_interface_dependant_file,
            base_schema,
        )

    # def assert_is_accepted_format(self, value: TypedDict()):

    @classmethod
    def clean_upload_dirs(cls) -> None:
        # Delete files uploaded from API
        for upload_dir in cls._upload_dirs:
            if upload_dir.exists():
                shutil.rmtree(upload_dir)

    def parse_interface_dependant_file(self, value: AnyFile) -> Path:
        pass

def serialize_bool(value: bool | None) -> int | None:
    # Looks like pydantic infers serialization based on function types
    # so no need to actually parse `value` to int
    print("bool serialize", value)
    return value


def main():
    class Test(BaseModel):
        # s1: int
        # s3: Annotated[bool, PlainSerializer(serialize_bool, when_used="json-unless-none")]
        # l1: Annotated[list[str], ListConstraints()]
        # l2: Annotated[list[int], ListConstraints()]
        l3: Annotated[
            list[
                Annotated[
                    bool, PlainSerializer(serialize_bool, when_used="json-unless-none")
                ]
            ]
            | None,
            ListConstraints(),
        ]

    model_input = {
        "s1": "10",
        "s3": "0",
        "l1": "a,b,c",
        "l2": "1,2,3",
        "l3": "1,0,1",
    }
    model = Test(**model_input)
    model.model_validate(model_input, context={"choices": [1]})
    print("MODEL", model)
    print("INPUT", model_input)
    print("DUMP_PYTHON", model.model_dump())
    print("DUMP_BASH", model.model_dump(mode="json"))


if __name__ == "__main__":
    main()
