from __future__ import annotations

from pcap2llm.web.security import (
    WebValidationError,
    validate_profile_name,
    validate_string_length,
)


def test_validate_profile_name_valid() -> None:
    """Test valid profile names."""
    valid = [
        "Default Profile",
        "High-Security",
        "Test_Profile_123",
        "P.1-2_3 x",
        "A",  # Single char OK
    ]
    for name in valid:
        validate_profile_name(name)  # Should not raise


def test_validate_profile_name_invalid() -> None:
    """Test invalid profile names."""
    invalid = [
        "",  # Empty
        "a" * 256,  # Too long
        "Profile@Name",  # Invalid chars (@ not allowed)
        "Profile#Name",  # Invalid chars (# not allowed)
        "Profile/Name",  # Invalid chars (/ not allowed)
        "Profile\\Name",  # Invalid chars (\ not allowed)
        "Profile$Name",  # Invalid chars ($ not allowed)
        "Profile&Name",  # Invalid chars (& not allowed)
        "Profile;Name",  # Invalid chars (; not allowed)
    ]
    for name in invalid:
        try:
            validate_profile_name(name)
            assert False, f"Expected validation to fail for '{name}'"
        except WebValidationError:
            pass


def test_validate_string_length_valid() -> None:
    """Test string length validation with valid inputs."""
    validate_string_length("Hello", 10, "Test")
    validate_string_length("", 10, "Test")  # Empty is OK
    validate_string_length("Max length test", 15, "Test")
    validate_string_length(None, 10, "Test")  # None is OK


def test_validate_string_length_invalid() -> None:
    """Test string length validation with invalid inputs."""
    try:
        validate_string_length("This is too long", 10, "Test")
        assert False, "Expected validation to fail"
    except WebValidationError as exc:
        assert "exceeds maximum length" in str(exc)
