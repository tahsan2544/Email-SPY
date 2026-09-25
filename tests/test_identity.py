from emailscope.modules.identity import (
    analyse,
    handles_from_local,
    handles_from_name,
    parse_email,
)


def test_valid_address_is_decomposed():
    identity = parse_email("  John.Doe+news@Example.COM ")
    assert identity.valid
    assert identity.email == "john.doe+news@example.com"
    assert identity.local == "john.doe+news"
    assert identity.domain == "example.com"
    assert identity.tag == "news"


def test_invalid_addresses_are_reported_not_raised():
    for raw in ("", "nope", "a@b", "@example.com", "john..doe@example"):
        identity = parse_email(raw)
        assert not identity.valid
        assert identity.problems


def test_free_provider_detection():
    assert parse_email("someone@gmail.com").provider == "Google Gmail"
    assert parse_email("someone@gmail.com").is_free_provider
    assert parse_email("someone@corp-internals.example").provider is None


def test_disposable_detection():
    assert parse_email("throwaway@mailinator.com").is_disposable
    assert not parse_email("throwaway@proton.me").is_disposable


def test_name_candidates_from_dotted_local_part():
    assert "John Doe" in parse_email("john.doe@example.com").name_candidates
    assert "Doe John" in parse_email("john.doe@example.com").name_candidates


def test_name_candidates_ignore_plus_tag_and_digits():
    candidates = parse_email("john.doe99+newsletter@example.com").name_candidates
    assert candidates[0] == "John Doe"


def test_opaque_local_part_yields_no_name():
    assert parse_email("x7q2p9@example.com").name_candidates == []


def test_handle_candidates_for_simple_local_part():
    assert handles_from_local("matt") == ["matt"]


def test_handle_candidates_variants():
    handles = handles_from_local("john.doe")
    for expected in ("john.doe", "johndoe", "jdoe", "johnd", "john_doe"):
        assert expected in handles


def test_handles_from_observed_name():
    handles = handles_from_name("Matt Mullenweg")
    for expected in ("mattmullenweg", "matt.mullenweg", "mullenweg", "mmullenweg"):
        assert expected in handles


def test_handles_from_single_word_name():
    assert handles_from_name("Plato") == ["plato"]


def test_gravatar_hashes_match_reference_vectors():
    identity = parse_email("user@example.com")
    assert identity.gravatar_md5 == "b58996c504c5638798eb6b511e6f49af"
    assert len(identity.gravatar_sha256) == 64


def test_analyse_returns_finding_for_valid_address():
    finding = analyse("someone@gmail.com")
    assert finding.module == "identity"
    assert finding.status == "info"
    assert finding.data["provider"] == "Google Gmail"


def test_analyse_returns_error_for_invalid_address():
    finding = analyse("not-an-email")
    assert finding.status == "error"
    assert finding.data["valid"] is False
