"""Tests para strip_select_before_scalar_func (lógica pura compartida
entre el tamper real de sqlmap y WAFBypassProber).
"""

from inyector.utils.scalar_func_bypass import strip_select_before_scalar_func


def test_strips_select_before_known_scalar_function():
    assert strip_select_before_scalar_func("(SELECT DATABASE())") == "(DATABASE())"


def test_strips_select_with_inline_comment_separator():
    assert (
        strip_select_before_scalar_func("(SELECT/**/CURRENT_USER())")
        == "(CURRENT_USER())"
    )


def test_leaves_select_from_untouched():
    # No debe tocar un SELECT ... FROM real -- solo el patrón
    # SELECT+función-escalar-sin-FROM.
    payload = "SELECT username FROM users"
    assert strip_select_before_scalar_func(payload) == payload


def test_empty_payload_returns_as_is():
    assert strip_select_before_scalar_func("") == ""
    assert strip_select_before_scalar_func(None) is None
