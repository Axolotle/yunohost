#
# Copyright (c) 2023 YunoHost Contributors
#
# This file is part of YunoHost (see https://yunohost.org)
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.
#
from rich import print
import sys
import os
import string
import subprocess
import yaml
from typing import Any, Literal, get_args
from dataclasses import dataclass

SMALL_PWD_LIST = [
    "yunohost",
    "olinuxino",
    "olinux",
    "raspberry",
    "admin",
    "root",
    "test",
    "rpi",
]

#
# 100k firsts "most used password" with length 8+
#
# List obtained with:
# curl -L https://github.com/danielmiessler/SecLists/raw/master/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt \
# | grep -v -E "^[a-zA-Z0-9]{1,7}$" | head -n 100000 | gzip > 100000-most-used-passwords-length8plus.txt.gz
#
MOST_USED_PASSWORDS = "/usr/share/yunohost/100000-most-used-passwords-length8plus.txt"

# Length, digits, lowers, uppers, others
STRENGTH_LEVELS = [
    (8, 0, 0, 0, 0),
    (8, 1, 1, 1, 0),
    (8, 1, 1, 1, 1),
    (12, 1, 1, 1, 1),
]


def redact_value(value):
    import urllib.parse
    from yunohost.log import OperationLogger

    # Tell the operation_logger to redact all password-type / secret args
    # Also redact the % escaped version of the password that might appear in
    # the 'args' section of metadata (relevant for password with non-alphanumeric char)
    data_to_redact = []
    if value and isinstance(value, str):
        data_to_redact.append(value)

    data_to_redact += [
        urllib.parse.quote(data)
        for data in data_to_redact
        if urllib.parse.quote(data) != data
    ]

    for operation_logger in OperationLogger._instances:
        operation_logger.data_to_redact.extend(data_to_redact)

    return value


def assert_password_is_compatible(password):
    """
    UNIX seems to not like password longer than 127 chars ...
    e.g. SSH login gets broken (or even 'su admin' when entering the password)
    """

    if len(password) >= 127:
        # Note that those imports are made here and can't be put
        # on top (at least not the moulinette ones)
        # because the moulinette needs to be correctly initialized
        # as well as modules available in python's path.
        from yunohost.utils.error import YunohostValidationError

        raise YunohostValidationError("password_too_long")


Profile = Literal["user", "admin"]


def assert_password_is_strong_enough(profile: Profile, password: str | None):
    from typing import Annotated
    from pydantic import TypeAdapter

    return TypeAdapter(
        Annotated[str, PasswordConstraints(profile=profile)]
    ).validate_python(password)


def get_validation_strength(profile: Profile):
    try:
        # We do this "manually" instead of using settings_get()
        # from settings.py because this file is also meant to be
        # use as a script by ssowat.
        # (or at least that's my understanding -- Alex)
        settings = yaml.safe_load(open("/etc/yunohost/settings.yml", "r"))
        setting_key = profile + "_strength"
        return int(settings[setting_key])
    except Exception:
        # Fallback to default value if we can't fetch settings for some reason
        return 1


@dataclass
class PasswordConstraints:
    """
    Initialize a password validator.

    The profile shall be either "user" or "admin"
    and will correspond to a validation strength
    defined via the setting "security.password.<profile>_strength"
    """

    profile: Profile = "user"
    validation_strength: int = 1
    forbidden_chars: str | None = None

    def validation_summary(self, password):
        """
        Check if a password is listed in the list of most used password
        and if the overall strength is good enough compared to the
        validation_strength defined in the constructor.

        Produces a summary-tuple comprised of a level (succes or error)
        and a message key describing the issues found.
        """
        self.validation_strength = get_validation_strength(self.profile)

        if self.validation_strength < 0:
            return ("success", "")

        try:
            self.assert_strong_enough(password)
            self.assert_not_in_most_used_list(password)
        except ValueError as e:
            return ("error", e.msg)

        return ("success", "")

    def __get_pydantic_core_schema__(self, source_type, handler):
        from pydantic_core import core_schema

        self.validation_strength = get_validation_strength(self.profile)
        nullable = type(None) in get_args(source_type)

        def strip_and_parse_empty_str_to_none(v: Any):
            if isinstance(v, str):
                v = v.strip()
                return None if v == "" else v
            return v

        schema = core_schema.chain_schema(
            [
                core_schema.is_instance_schema(str),
                core_schema.no_info_plain_validator_function(
                    self.assert_strong_enough,
                ),
                core_schema.no_info_plain_validator_function(
                    self.assert_not_in_most_used_list
                ),
                core_schema.no_info_plain_validator_function(redact_value),
            ]
        )
        schema = core_schema.nullable_schema(schema) if nullable else schema
        return core_schema.no_info_before_validator_function(
            strip_and_parse_empty_str_to_none, schema
        )

    def assert_strong_enough(self, value: str) -> str:
        """
        Returns the strength of a password, defined as a tuple
        containing the length of the password, the number of digits,
        lowercase letters, uppercase letters, and other characters.

        For instance, "PikachuDu67" is (11, 2, 7, 2, 0)

        Computes the strength of a password and compares
        it to the STRENGTH_LEVELS.

        Returns an int corresponding to the highest STRENGTH_LEVEL
        satisfied by the password.
        """

        if any(char in value for char in (self.forbidden_chars or "")):
            raise ValueError(f"forbidden characters in string: {self.forbidden_chars}")

        length = len(value)
        digits = 0
        uppers = 0
        lowers = 0
        others = 0

        for character in value:
            if character in string.digits:
                digits = digits + 1
            elif character in string.ascii_uppercase:
                uppers = uppers + 1
            elif character in string.ascii_lowercase:
                lowers = lowers + 1
            else:
                others = others + 1

        strength = (length, digits, lowers, uppers, others)

        strength_level = 0
        # Iterate over each level and its criterias
        for level, level_criterias in enumerate(STRENGTH_LEVELS):
            # Iterate simulatenously over the level criterias (e.g. [8, 1, 1, 1, 0])
            # and the strength of the password (e.g. [11, 2, 7, 2, 0])
            # and compare the values 1-by-1.
            # If one False is found, the password does not satisfy the level
            if False in [s >= c for s, c in zip(strength, level_criterias)]:
                break
            # Otherwise, the strength of the password is at least of the current level.
            strength_level = level + 1

        if strength_level < self.validation_strength:
            # i18n: password_too_simple_1
            # i18n: password_too_simple_2
            # i18n: password_too_simple_3
            # i18n: password_too_simple_4
            raise ValueError(f"password_too_simple_{self.validation_strength}")

        return value

    def assert_not_in_most_used_list(self, value: str) -> str:
        if value in SMALL_PWD_LIST:
            raise ValueError("password_listed")

        # Decompress file if compressed
        if os.path.exists("%s.gz" % MOST_USED_PASSWORDS):
            os.system("gzip -fd %s.gz" % MOST_USED_PASSWORDS)

        # Grep the password in the file
        # We use '-f -' to feed the pattern (= the password) through
        # stdin to avoid it being shown in ps -ef --forest...
        command = "grep -q -F -f - %s" % MOST_USED_PASSWORDS
        p = subprocess.Popen(command.split(), stdin=subprocess.PIPE)
        p.communicate(input=value.encode("utf-8"))

        if not bool(p.returncode):
            # i18n: password_listed
            raise ValueError("password_listed")

        return value


# This file is also meant to be used as an executable by
# SSOwat to validate password from the portal when an user
# change its password.
if __name__ == "__main__":
    if len(sys.argv) < 2:
        import getpass

        pwd = getpass.getpass("")
        # print("usage: password.py PASSWORD")
    else:
        pwd = sys.argv[1]
    status, msg = PasswordConstraints(profile="user").validation_summary(pwd)
    print(msg)
    sys.exit(0)
