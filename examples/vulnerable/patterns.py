"""Intentionally vulnerable regex patterns, for demo and test purposes only.

Do not copy these into real code; see examples/safe/patterns.py for the
corrected versions.
"""
import re

NESTED_QUANTIFIER = re.compile(r"^(a+)+$")
OPTIONAL_NESTED = re.compile(r"^([a-zA-Z0-9_.-]+)*@")
DUPLICATE_ALTERNATION = re.compile(r"^(a|a)+$")
OVERLAPPING_PLUS_CHAIN = re.compile(r"^\s*\s*\s*$")
DOT_STAR_CHAIN = re.compile(r"^.*.*=.*$")
HTML_TAG = re.compile(r"<([a-z]+)([^<]+)*(?:>(.*)<\/\1>|\s+\/>)")
