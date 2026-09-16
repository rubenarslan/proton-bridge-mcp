"""Unit tests for the helpers and gates in proton_bridge_mcp.

Most of these exercise the side-effect-free helpers: header decoding, address
parsing, IMAP-quoting, body extraction, attachment resolution, and IMAP-search
criteria construction. A few exercise tool bodies, but only with the network
seams (`_imap_call`, `_smtp_deliver`, `_append_to_sent`, `_resolve_password`)
replaced by recorders, or on refusal paths that short-circuit before any
connection is opened. Nothing here opens a socket or reads the keychain; the
real IMAP/SMTP paths need integration coverage with a running Bridge.
"""
from __future__ import annotations

import asyncio
import email
import json
import re
from email.message import EmailMessage

import pytest
from pydantic import ValidationError

import proton_bridge_mcp as pbm


# ----------------------------------------------------------------------------
# _decode_header
# ----------------------------------------------------------------------------
class TestDecodeHeader:
    def test_none_returns_empty_string(self):
        assert pbm._decode_header(None) == ""

    def test_plain_ascii_passes_through(self):
        assert pbm._decode_header("Hello, world") == "Hello, world"

    def test_bytes_decoded_as_utf8(self):
        assert pbm._decode_header("Olá".encode("utf-8")) == "Olá"

    def test_latin1_fallback_on_invalid_utf8(self):
        # Bytes that are not valid UTF-8 should still decode to *some* string
        # rather than raise. The current implementation replaces invalid
        # sequences; the property under test is "no exception, returns str".
        out = pbm._decode_header(b"\xc3\x28")  # invalid utf-8
        assert isinstance(out, str)
        assert out  # non-empty

    def test_rfc2047_qp_encoded_word(self):
        # =?UTF-8?Q?Caf=C3=A9?= → "Café"
        assert pbm._decode_header("=?UTF-8?Q?Caf=C3=A9?=") == "Café"

    def test_rfc2047_base64_encoded_word(self):
        # "Hello" in UTF-8 base64
        assert pbm._decode_header("=?utf-8?B?SGVsbG8=?=") == "Hello"

    def test_mixed_encoded_and_plain(self):
        out = pbm._decode_header("=?UTF-8?Q?Caf=C3=A9?= - lunch")
        assert "Café" in out
        assert "lunch" in out


# ----------------------------------------------------------------------------
# _iso_date
# ----------------------------------------------------------------------------
class TestIsoDate:
    def test_none_returns_none(self):
        assert pbm._iso_date(None) is None

    def test_empty_string_returns_none(self):
        assert pbm._iso_date("") is None

    def test_valid_rfc2822_returns_iso(self):
        out = pbm._iso_date("Mon, 09 Mar 2026 14:30:00 +0000")
        # We don't pin the exact tz offset (depends on the runner) but we
        # require: ISO format, 2026, March, the 9th.
        assert out is not None
        assert "2026-03-09" in out
        assert "T" in out  # ISO 8601 separator

    def test_malformed_returns_input_unchanged_or_none(self):
        # Implementation choice: parsedate_to_datetime may return None for
        # garbage. Whatever happens, the helper must not raise.
        out = pbm._iso_date("not a date at all")
        assert out is None or "not a date" in out


# ----------------------------------------------------------------------------
# _quote (IMAP string quoting)
# ----------------------------------------------------------------------------
class TestQuote:
    def test_simple_string(self):
        assert pbm._quote("hello") == '"hello"'

    def test_escapes_double_quote(self):
        assert pbm._quote('say "hi"') == r'"say \"hi\""'

    def test_escapes_backslash(self):
        assert pbm._quote(r"a\b") == r'"a\\b"'

    def test_escapes_both_backslash_and_quote(self):
        assert pbm._quote(r'a\"b') == r'"a\\\"b"'

    def test_empty_string(self):
        assert pbm._quote("") == '""'


# ----------------------------------------------------------------------------
# _addr_struct
# ----------------------------------------------------------------------------
class TestAddrStruct:
    def test_empty_returns_empty_list(self):
        assert pbm._addr_struct("") == []

    def test_single_bare_address(self):
        out = pbm._addr_struct("alice@example.com")
        assert out == [{"name": "", "email": "alice@example.com"}]

    def test_single_with_display_name(self):
        out = pbm._addr_struct("Alice <alice@example.com>")
        assert out == [{"name": "Alice", "email": "alice@example.com"}]

    def test_multiple_addresses(self):
        out = pbm._addr_struct("Alice <alice@example.com>, bob@example.com")
        assert {"name": "Alice", "email": "alice@example.com"} in out
        assert {"name": "", "email": "bob@example.com"} in out
        assert len(out) == 2

    def test_rfc2047_in_display_name(self):
        out = pbm._addr_struct("=?UTF-8?Q?Caf=C3=A9?= <cafe@example.com>")
        assert out == [{"name": "Café", "email": "cafe@example.com"}]

    def test_drops_entries_without_email(self):
        # Display-only entries with no actual mailbox shouldn't survive.
        out = pbm._addr_struct("undisclosed-recipients:;")
        assert all(e["email"] for e in out)


# ----------------------------------------------------------------------------
# _parse_flags
# ----------------------------------------------------------------------------
class TestParseFlags:
    def test_no_flags_returns_empty(self):
        assert pbm._parse_flags("UID 42 RFC822.SIZE 1234") == []

    def test_seen_flag(self):
        assert pbm._parse_flags(r"FLAGS (\Seen) UID 42") == [r"\Seen"]

    def test_multiple_flags(self):
        assert pbm._parse_flags(r"FLAGS (\Seen \Flagged) UID 42") == [r"\Seen", r"\Flagged"]

    def test_empty_flags(self):
        assert pbm._parse_flags("FLAGS () UID 42") == []


# ----------------------------------------------------------------------------
# _extract_body
# ----------------------------------------------------------------------------
class TestExtractBody:
    def test_plain_only(self):
        msg = EmailMessage()
        msg["From"] = "a@b.com"
        msg["To"] = "c@d.com"
        msg["Subject"] = "test"
        msg.set_content("hello world")
        plain, html, attachments = pbm._extract_body(msg)
        assert "hello world" in plain
        assert html == ""
        assert attachments == []

    def test_html_only(self):
        msg = EmailMessage()
        msg["Subject"] = "test"
        msg.set_content("<p>hi</p>", subtype="html")
        plain, html, attachments = pbm._extract_body(msg)
        assert "<p>hi</p>" in html
        assert plain == ""
        assert attachments == []

    def test_multipart_alternative(self):
        msg = EmailMessage()
        msg["Subject"] = "test"
        msg.set_content("plain version")
        msg.add_alternative("<p>html version</p>", subtype="html")
        plain, html, attachments = pbm._extract_body(msg)
        assert "plain version" in plain
        assert "html version" in html
        assert attachments == []

    def test_attachment_metadata_only_no_payload(self):
        msg = EmailMessage()
        msg["Subject"] = "with attach"
        msg.set_content("see attached")
        msg.add_attachment(b"PDFCONTENT", maintype="application",
                           subtype="pdf", filename="report.pdf")
        plain, html, attachments = pbm._extract_body(msg)
        assert "see attached" in plain
        assert len(attachments) == 1
        attach = attachments[0]
        assert attach["filename"] == "report.pdf"
        assert attach["content_type"] == "application/pdf"
        assert attach["size_bytes"] > 0
        # Critical: attachment payload must NOT leak into the body.
        assert "PDFCONTENT" not in plain
        assert "PDFCONTENT" not in html

    def test_body_truncated_at_max_chars(self):
        big = "x" * (pbm.MAX_BODY_CHARS + 5000)
        msg = EmailMessage()
        msg["Subject"] = "huge"
        msg.set_content(big)
        plain, _, _ = pbm._extract_body(msg)
        assert len(plain) <= pbm.MAX_BODY_CHARS


# ----------------------------------------------------------------------------
# _build_search
# ----------------------------------------------------------------------------
class TestBuildSearch:
    def test_empty_returns_all(self):
        assert pbm._build_search() == ["ALL"]

    def test_single_from_filter(self):
        out = pbm._build_search(from_addr="alice@example.com")
        assert out[0] == "FROM"
        assert "alice@example.com" in out[1]

    def test_subject_filter_is_quoted(self):
        out = pbm._build_search(subject='hello "world"')
        assert "SUBJECT" in out
        # Embedded double-quotes must be escaped in the IMAP-quoted string.
        joined = " ".join(out)
        assert r'\"world\"' in joined

    def test_unseen_flag(self):
        out = pbm._build_search(unseen=True)
        assert "UNSEEN" in out

    def test_seen_flag(self):
        out = pbm._build_search(seen=True)
        assert "SEEN" in out

    def test_flagged_flag(self):
        out = pbm._build_search(flagged=True)
        assert "FLAGGED" in out

    def test_multiple_filters_combined(self):
        out = pbm._build_search(
            from_addr="alice@example.com",
            subject="invoice",
            unseen=True,
        )
        assert "FROM" in out
        assert "SUBJECT" in out
        assert "UNSEEN" in out

    def test_since_iso_date_converted_to_imap_format(self):
        out = pbm._build_search(since="2026-03-09")
        assert "SINCE" in out
        idx = out.index("SINCE")
        # IMAP wants DD-Mon-YYYY (e.g., "09-Mar-2026"); RFC 3501 §6.4.4.
        assert out[idx + 1] == "09-Mar-2026"

    def test_since_iso_datetime_with_z_converted(self):
        out = pbm._build_search(since="2026-03-09T14:30:00Z")
        idx = out.index("SINCE")
        assert out[idx + 1] == "09-Mar-2026"

    def test_not_keyword_emits_three_tokens(self):
        out = pbm._build_search(not_keyword="$Junk")
        assert out[:2] == ["NOT", "KEYWORD"]
        assert "$Junk" in out[2]


# ----------------------------------------------------------------------------
# _strip_invisibles (anti-prompt-injection: zero-width / bidi removal)
# ----------------------------------------------------------------------------
class TestStripInvisibles:
    def test_passes_through_normal_text(self):
        assert pbm._strip_invisibles("hello world") == "hello world"

    def test_preserves_ordinary_whitespace(self):
        assert pbm._strip_invisibles("a\tb\nc d") == "a\tb\nc d"

    def test_strips_zero_width_space(self):
        # U+200B between letters is invisible to humans, visible to models.
        assert pbm._strip_invisibles("hel​lo") == "hello"

    def test_strips_zero_width_joiner(self):
        assert pbm._strip_invisibles("a‍z") == "az"

    def test_strips_zero_width_non_joiner(self):
        assert pbm._strip_invisibles("a‌z") == "az"

    def test_strips_bidi_rlo(self):
        # RLO (U+202E) flips text rendering; classic spoofing vector.
        assert pbm._strip_invisibles("admin‮txt.exe") == "admintxt.exe"

    def test_strips_bidi_lro(self):
        assert pbm._strip_invisibles("a‭b") == "ab"

    def test_strips_isolate_chars(self):
        # U+2066-U+2069 are the newer bidi isolate controls.
        assert pbm._strip_invisibles("a⁦b⁩c") == "abc"

    def test_strips_bom_in_middle(self):
        assert pbm._strip_invisibles("a﻿b") == "ab"

    def test_strips_soft_hyphen(self):
        assert pbm._strip_invisibles("co­operate") == "cooperate"

    def test_strips_word_joiner(self):
        assert pbm._strip_invisibles("a⁠b") == "ab"

    def test_strips_line_separator(self):
        assert pbm._strip_invisibles("a b") == "ab"

    def test_empty_input_returns_empty(self):
        assert pbm._strip_invisibles("") == ""

    def test_combined_attack_string(self):
        # Mix of zero-width + bidi + soft hyphen, simulating a steg payload.
        attack = "se​nd­ mo‮ney"
        assert pbm._strip_invisibles(attack) == "send money"


# ----------------------------------------------------------------------------
# _wrap_untrusted (provenance-tagged data delimiters)
# ----------------------------------------------------------------------------
class TestWrapUntrusted:
    def test_includes_preamble_signalling_data_not_instructions(self):
        out = pbm._wrap_untrusted("hi")
        assert "untrusted" in out.lower()
        assert "data" in out.lower()
        assert "instructions" in out.lower()

    def test_open_and_close_tags_share_nonce(self):
        out = pbm._wrap_untrusted("hi")
        m = re.search(r"<UNTRUSTED_EMAIL_BODY_([a-f0-9]+)", out)
        assert m, f"open tag not found in: {out!r}"
        nonce = m.group(1)
        assert len(nonce) >= 4  # secrets.token_hex(3) -> 6 hex chars
        assert f"</UNTRUSTED_EMAIL_BODY_{nonce}>" in out

    def test_nonce_changes_per_call(self):
        # 8 calls; 6-hex-char nonces collide with prob ~1/16M per pair.
        # Failing this test almost certainly means the RNG is broken.
        nonces = set()
        for _ in range(8):
            out = pbm._wrap_untrusted("x")
            m = re.search(r"<UNTRUSTED_EMAIL_BODY_([a-f0-9]+)", out)
            nonces.add(m.group(1))
        assert len(nonces) >= 7

    def test_provenance_attributes_in_open_tag(self):
        out = pbm._wrap_untrusted("hi", source="alice@example.com", subject="invoice")
        assert 'source="alice@example.com"' in out
        assert 'subject="invoice"' in out

    def test_invisibles_stripped_from_provenance_attrs(self):
        # Even attribute values must be sanitised, since they're part of
        # what the model reads.
        out = pbm._wrap_untrusted("hi", subject="in​voice")
        assert 'subject="invoice"' in out

    def test_double_quotes_in_attr_replaced_to_avoid_breaking_tag(self):
        # The wrapper uses double-quoted attrs; an attacker-controlled
        # subject containing " must not be able to close the attr early.
        out = pbm._wrap_untrusted("hi", subject='evil"injected')
        assert 'evil"injected' not in out  # raw " must be replaced
        # ' substitution keeps the value visible without breaking the tag.
        assert "evil'injected" in out

    def test_kind_can_be_overridden(self):
        out = pbm._wrap_untrusted("hi", kind="EMAIL_BODY_HTML")
        assert "<UNTRUSTED_EMAIL_BODY_HTML_" in out
        assert "</UNTRUSTED_EMAIL_BODY_HTML_" in out

    def test_content_passed_through_verbatim(self):
        # The wrapper sanitises *attrs*; the *content* is the caller's
        # responsibility (in practice it has already passed through
        # _strip_invisibles via _decode_header / _extract_body).
        out = pbm._wrap_untrusted("inner content here")
        assert "inner content here" in out

    def test_empty_provenance_attrs_omitted(self):
        # falsy values (None, "") shouldn't appear as empty attrs.
        out = pbm._wrap_untrusted("hi", source="alice@example.com", subject="")
        assert 'source="alice@example.com"' in out
        assert 'subject=""' not in out


# ----------------------------------------------------------------------------
# _parse_authentication_results (RFC 8601 spf/dkim/dmarc extraction)
# ----------------------------------------------------------------------------
class TestParseAuthenticationResults:
    @staticmethod
    def _msg(headers: str) -> "email.message.Message":
        return email.message_from_string(headers + "\nSubject: hi\n\nbody\n")

    def test_no_header_returns_empty(self):
        assert pbm._parse_authentication_results(self._msg("")) == {}

    def test_all_pass(self):
        m = self._msg(
            "Authentication-Results: mx.proton.me; "
            "spf=pass smtp.mailfrom=alice@example.com; "
            "dkim=pass header.d=example.com header.s=sel1; "
            "dmarc=pass action=none header.from=example.com"
        )
        assert pbm._parse_authentication_results(m) == {
            "spf": "pass", "dkim": "pass", "dmarc": "pass",
        }

    def test_mixed_pass_and_fail(self):
        m = self._msg(
            "Authentication-Results: mx.proton.me; spf=fail; dkim=pass; dmarc=fail"
        )
        assert pbm._parse_authentication_results(m) == {
            "spf": "fail", "dkim": "pass", "dmarc": "fail",
        }

    def test_uppercase_normalised_to_lowercase(self):
        m = self._msg("Authentication-Results: mx.proton.me; SPF=PASS; DKIM=Fail")
        assert pbm._parse_authentication_results(m) == {"spf": "pass", "dkim": "fail"}

    def test_only_some_methods_present(self):
        m = self._msg("Authentication-Results: mx.proton.me; spf=pass")
        assert pbm._parse_authentication_results(m) == {"spf": "pass"}

    def test_first_header_wins_per_method(self):
        # Multiple A-R headers from different MTAs. The closer one (added by
        # our own MX, conventionally topmost) takes precedence.
        m = self._msg(
            "Authentication-Results: mx.proton.me; spf=pass; dkim=pass\n"
            "Authentication-Results: relay.upstream.example; spf=fail; dkim=fail"
        )
        out = pbm._parse_authentication_results(m)
        assert out["spf"] == "pass"
        assert out["dkim"] == "pass"

    def test_garbage_header_returns_empty(self):
        m = self._msg("Authentication-Results: not a structured header value")
        assert pbm._parse_authentication_results(m) == {}

    def test_dmarc_none_passes_through(self):
        # `dmarc=none` is a real value (no DMARC policy published);
        # not the same as the header being missing.
        m = self._msg("Authentication-Results: mx.proton.me; dmarc=none")
        assert pbm._parse_authentication_results(m) == {"dmarc": "none"}

    def test_softfail_and_temperror_preserved(self):
        m = self._msg(
            "Authentication-Results: mx.proton.me; "
            "spf=softfail; dkim=temperror; dmarc=permerror"
        )
        assert pbm._parse_authentication_results(m) == {
            "spf": "softfail", "dkim": "temperror", "dmarc": "permerror",
        }


# ----------------------------------------------------------------------------
# Integration: invisibles get stripped through the public helpers
# ----------------------------------------------------------------------------
class TestSanitisationIntegration:
    def test_decode_header_strips_zero_width(self):
        # An attacker-controlled subject with embedded ZWSP should arrive at
        # the LLM cleanly, not with the steg payload intact.
        assert pbm._decode_header("Pa​yPal alert") == "PayPal alert"

    def test_decode_header_strips_bidi_override(self):
        assert pbm._decode_header("admin‮txt.exe") == "admintxt.exe"

    def test_extract_body_strips_invisibles_in_plain_text(self):
        msg = EmailMessage()
        msg["Subject"] = "test"
        msg.set_content("se​nd mo‮ney")
        plain, _, _ = pbm._extract_body(msg)
        assert "send money" in plain
        assert "​" not in plain
        assert "‮" not in plain

    def test_extract_body_strips_invisibles_in_html(self):
        msg = EmailMessage()
        msg["Subject"] = "test"
        msg.set_content("<p>se​nd</p>", subtype="html")
        _, html, _ = pbm._extract_body(msg)
        assert "<p>send</p>" in html
        assert "​" not in html

    def test_addr_struct_strips_invisibles_in_display_name(self):
        # Display names go through _decode_header, so they inherit the
        # sanitisation. A spoofed display name carrying RLO should arrive
        # cleaned up.
        out = pbm._addr_struct("Pa​yPal <attacker@evil.com>")
        assert out == [{"name": "PayPal", "email": "attacker@evil.com"}]


# ----------------------------------------------------------------------------
# Destructive-tool acknowledgement gating
# ----------------------------------------------------------------------------
class TestSendEmailInputRequiresAck:
    """`acknowledged` is a server-enforced anti-coercion check on send."""

    def test_omitting_acknowledged_raises(self):
        with pytest.raises(ValidationError):
            pbm.SendEmailInput(
                to=["a@b.com"], subject="hi", body_text="hello",
            )

    def test_acknowledged_true_validates(self):
        m = pbm.SendEmailInput(
            to=["a@b.com"], subject="hi", body_text="hello", acknowledged=True,
        )
        assert m.acknowledged is True

    def test_acknowledged_false_validates_at_input_layer(self):
        # The bool itself is structurally valid; refusal happens in the
        # tool body (verified separately by TestRefusedUnack).
        m = pbm.SendEmailInput(
            to=["a@b.com"], subject="hi", body_text="hello", acknowledged=False,
        )
        assert m.acknowledged is False


class TestDeleteInputRequiresAck:
    """`acknowledged` is a server-enforced anti-coercion check on delete."""

    def test_omitting_acknowledged_raises(self):
        with pytest.raises(ValidationError):
            pbm.DeleteInput(uid="42")

    def test_omitting_acknowledged_raises_even_with_expunge(self):
        # The expunge flag does not satisfy the requirement; explicit
        # acknowledged=true is still required for a permanent delete.
        with pytest.raises(ValidationError):
            pbm.DeleteInput(uid="42", expunge=True)

    def test_acknowledged_true_validates(self):
        m = pbm.DeleteInput(uid="42", acknowledged=True)
        assert m.acknowledged is True

    def test_acknowledged_false_validates_at_input_layer(self):
        m = pbm.DeleteInput(uid="42", acknowledged=False)
        assert m.acknowledged is False


class TestRefusedUnack:
    def test_refusal_shape_for_send(self):
        data = json.loads(pbm._refused_unack("proton_send_email"))
        assert data["status"] == "refused"
        assert data["reason"] == "acknowledged_required"
        assert data["action"] == "proton_send_email"
        assert "acknowledged" in data["message"].lower()
        assert "prompt injection" in data["message"].lower()

    def test_refusal_shape_for_delete(self):
        data = json.loads(pbm._refused_unack("proton_delete_email"))
        assert data["action"] == "proton_delete_email"
        assert data["status"] == "refused"

    def test_refusal_shape_for_create_draft(self):
        data = json.loads(pbm._refused_unack("proton_create_draft"))
        assert data["action"] == "proton_create_draft"
        assert data["status"] == "refused"
        assert data["reason"] == "acknowledged_required"

    def test_refusal_shape_for_download_attachment(self):
        data = json.loads(pbm._refused_unack("proton_download_attachment"))
        assert data["action"] == "proton_download_attachment"
        assert data["status"] == "refused"


class TestCreateDraftInputRequiresAck:
    """`acknowledged` is required at the input layer so a model has to
    consciously decide. The body-level external-recipient gate decides
    whether `acknowledged=False` is actually refused."""

    def test_omitting_acknowledged_raises(self):
        with pytest.raises(ValidationError):
            pbm.CreateDraftInput(to=["a@b.com"], subject="hi", body_text="hello")

    def test_acknowledged_true_validates(self):
        m = pbm.CreateDraftInput(
            to=["a@b.com"], subject="hi", body_text="hello", acknowledged=True,
        )
        assert m.acknowledged is True

    def test_acknowledged_false_validates_at_input_layer(self):
        # Structurally valid; the tool body decides whether to refuse based
        # on whether any recipient is external.
        m = pbm.CreateDraftInput(
            to=["a@b.com"], subject="hi", body_text="hello", acknowledged=False,
        )
        assert m.acknowledged is False


class TestDownloadAttachmentInputRequiresAck:
    """Writing attachment bytes to a user-supplied path is a side effect
    outside the model's sandbox; the field is required."""

    def test_omitting_acknowledged_raises(self):
        with pytest.raises(ValidationError):
            pbm.DownloadAttachmentInput(
                uid="42", filename="report.pdf", save_path="/tmp/r.pdf",
            )

    def test_acknowledged_true_validates(self):
        m = pbm.DownloadAttachmentInput(
            uid="42", filename="report.pdf", save_path="/tmp/r.pdf",
            acknowledged=True,
        )
        assert m.acknowledged is True

    def test_acknowledged_false_validates_at_input_layer(self):
        m = pbm.DownloadAttachmentInput(
            uid="42", filename="report.pdf", save_path="/tmp/r.pdf",
            acknowledged=False,
        )
        assert m.acknowledged is False


class TestExternalRecipients:
    """Self-address detection for the draft-recipient gate."""

    def test_no_self_addresses_treats_all_as_external(self, monkeypatch):
        monkeypatch.setattr(pbm, "BRIDGE_USER", "")
        monkeypatch.setattr(pbm, "DEFAULT_FROM", "")
        out = pbm._external_recipients(["a@b.com"], None, None)
        assert out == ["a@b.com"]

    def test_self_address_excluded(self, monkeypatch):
        monkeypatch.setattr(pbm, "BRIDGE_USER", "me@example.com")
        monkeypatch.setattr(pbm, "DEFAULT_FROM", "me@example.com")
        out = pbm._external_recipients(["me@example.com"], None, None)
        assert out == []

    def test_mixed_self_and_external(self, monkeypatch):
        monkeypatch.setattr(pbm, "BRIDGE_USER", "me@example.com")
        monkeypatch.setattr(pbm, "DEFAULT_FROM", "me@example.com")
        out = pbm._external_recipients(
            ["me@example.com", "attacker@evil.com"], None, None,
        )
        assert out == ["attacker@evil.com"]

    def test_case_insensitive_self_match(self, monkeypatch):
        monkeypatch.setattr(pbm, "BRIDGE_USER", "Me@Example.com")
        monkeypatch.setattr(pbm, "DEFAULT_FROM", "me@example.com")
        out = pbm._external_recipients(["me@EXAMPLE.com"], None, None)
        assert out == []

    def test_default_from_alias_treated_as_self(self, monkeypatch):
        # User has BRIDGE_USER as primary but DEFAULT_FROM as an alias they
        # also own -- both should be treated as self.
        monkeypatch.setattr(pbm, "BRIDGE_USER", "primary@example.com")
        monkeypatch.setattr(pbm, "DEFAULT_FROM", "alias@example.com")
        assert pbm._external_recipients(["primary@example.com"], None, None) == []
        assert pbm._external_recipients(["alias@example.com"], None, None) == []

    def test_cc_and_bcc_also_checked(self, monkeypatch):
        monkeypatch.setattr(pbm, "BRIDGE_USER", "me@example.com")
        monkeypatch.setattr(pbm, "DEFAULT_FROM", "me@example.com")
        out = pbm._external_recipients(
            ["me@example.com"],
            cc=["copy@evil.com"],
            bcc=["blind@evil.com"],
        )
        assert sorted(out) == ["blind@evil.com", "copy@evil.com"]

    def test_display_name_form_extracted(self, monkeypatch):
        # `Alice <alice@example.com>` should be treated by its bare address.
        monkeypatch.setattr(pbm, "BRIDGE_USER", "me@example.com")
        monkeypatch.setattr(pbm, "DEFAULT_FROM", "me@example.com")
        out = pbm._external_recipients(
            ["Alice <alice@evil.com>", "Me <me@example.com>"], None, None,
        )
        assert out == ["alice@evil.com"]


# ----------------------------------------------------------------------------
# _locate_bridge_cert (path search; no network)
# ----------------------------------------------------------------------------
class TestLocateBridgeCert:
    def test_explicit_override_path_used_when_present(self, tmp_path, monkeypatch):
        # Override path takes precedence over the candidates list.
        cert = tmp_path / "cert.pem"
        cert.write_text("-----BEGIN CERTIFICATE-----\nstub\n-----END CERTIFICATE-----\n")
        monkeypatch.setattr(pbm, "BRIDGE_CERT_PATH", str(cert))
        assert pbm._locate_bridge_cert() == cert

    def test_explicit_override_missing_returns_none(self, monkeypatch, tmp_path):
        # Override pointing at a nonexistent file should *not* fall through to
        # the candidates list -- the user clearly meant *that* path.
        nope = tmp_path / "does-not-exist.pem"
        monkeypatch.setattr(pbm, "BRIDGE_CERT_PATH", str(nope))
        assert pbm._locate_bridge_cert() is None


# ----------------------------------------------------------------------------
# Attachment helpers
# ----------------------------------------------------------------------------
def _message_with_attachments():
    """A multipart message: plain + html bodies and two attachments, the
    second carrying a filename with path separators in it."""
    msg = EmailMessage()
    msg["From"] = "Alice <alice@example.com>"
    msg["To"] = "me@example.com"
    msg["Subject"] = "Quarterly report"
    msg["Date"] = "Mon, 09 Mar 2026 14:30:00 +0000"
    msg["Message-ID"] = "<abc@example.com>"
    msg.set_content("Please see the attached.")
    msg.add_alternative("<p>Please see the attached.</p>", subtype="html")
    msg.add_attachment(b"PDFBYTES", maintype="application", subtype="pdf",
                       filename="report.pdf")
    msg.add_attachment(b"CSVBYTES", maintype="text", subtype="csv",
                       filename="../../etc/data.csv")
    return msg


class TestSafeAttachmentName:
    def test_plain_name_passes_through(self):
        assert pbm._safe_attachment_name("report.pdf") == "report.pdf"

    def test_path_components_stripped(self):
        # Traversal in an attacker-supplied filename must not survive onto an
        # outgoing Content-Disposition, nor onto whatever saves it later.
        assert pbm._safe_attachment_name("../../etc/passwd") == "passwd"
        assert pbm._safe_attachment_name("C:\\Windows\\evil.exe") == "evil.exe"

    def test_control_characters_stripped(self):
        # A newline in a filename is a header-injection vector.
        assert pbm._safe_attachment_name("in\r\nvoice.pdf") == "invoice.pdf"
        assert pbm._safe_attachment_name("nul\x00.txt") == "nul.txt"

    def test_invisible_unicode_stripped(self):
        assert pbm._safe_attachment_name("in\u200bvoice.pdf") == "invoice.pdf"

    def test_empty_and_dot_names_fall_back(self):
        assert pbm._safe_attachment_name("") == "attachment.bin"
        assert pbm._safe_attachment_name("   ") == "attachment.bin"
        assert pbm._safe_attachment_name("..") == "attachment.bin"
        assert pbm._safe_attachment_name("/") == "attachment.bin"
        assert pbm._safe_attachment_name(None, fallback="x.bin") == "x.bin"

    def test_long_name_truncated(self):
        assert len(pbm._safe_attachment_name("a" * 500)) == 200


class TestSplitContentType:
    def test_declared_type_used(self):
        assert pbm._split_content_type("application/pdf", "x.bin") == ("application", "pdf")

    def test_generic_octet_stream_guessed_from_filename(self):
        assert pbm._split_content_type("application/octet-stream", "notes.txt") == ("text", "plain")

    def test_missing_type_guessed_from_filename(self):
        assert pbm._split_content_type(None, "photo.png") == ("image", "png")

    def test_unguessable_falls_back_to_octet_stream(self):
        assert pbm._split_content_type(None, "blob") == ("application", "octet-stream")

    def test_malformed_type_falls_back(self):
        assert pbm._split_content_type("nonsense", "blob") == ("application", "octet-stream")

    def test_case_normalised(self):
        assert pbm._split_content_type("APPLICATION/PDF", "x") == ("application", "pdf")


class TestCollectAttachmentParts:
    def test_indexes_are_one_based_and_in_walk_order(self):
        parts = pbm._collect_attachment_parts(_message_with_attachments())
        assert [i for i, _ in parts] == [1, 2]
        assert parts[0][1].get_filename() == "report.pdf"

    def test_body_only_message_has_no_attachments(self):
        msg = EmailMessage()
        msg.set_content("just text")
        assert pbm._collect_attachment_parts(msg) == []


class TestMessageAttachmentBlobs:
    def test_all_attachments_by_default(self):
        blobs = pbm._message_attachment_blobs(
            _message_with_attachments(), mailbox="INBOX", uid="42")
        assert [b.filename for b in blobs] == ["report.pdf", "data.csv"]
        assert blobs[0].data == b"PDFBYTES"
        assert (blobs[0].maintype, blobs[0].subtype) == ("application", "pdf")

    def test_origin_records_provenance(self):
        blobs = pbm._message_attachment_blobs(
            _message_with_attachments(), mailbox="Archive", uid="7")
        assert blobs[0].origin == "Archive:uid=7:#1"
        assert blobs[0].describe()["source"] == "Archive:uid=7:#1"

    def test_select_by_filename(self):
        blobs = pbm._message_attachment_blobs(
            _message_with_attachments(), mailbox="INBOX", uid="42",
            filename="report.pdf")
        assert [b.filename for b in blobs] == ["report.pdf"]

    def test_select_by_index(self):
        blobs = pbm._message_attachment_blobs(
            _message_with_attachments(), mailbox="INBOX", uid="42", index=2)
        assert blobs[0].data == b"CSVBYTES"

    def test_filename_match_is_on_the_raw_name_not_the_sanitised_one(self):
        # The model sees the decoded name in the attachment listing, so that's
        # what it passes back; sanitisation happens on the way out.
        blobs = pbm._message_attachment_blobs(
            _message_with_attachments(), mailbox="INBOX", uid="42",
            filename="../../etc/data.csv")
        assert blobs[0].filename == "data.csv"

    def test_duplicate_filenames_all_returned(self):
        msg = EmailMessage()
        msg.set_content("two invoices")
        msg.add_attachment(b"ONE", maintype="application", subtype="pdf",
                           filename="invoice.pdf")
        msg.add_attachment(b"TWO", maintype="application", subtype="pdf",
                           filename="invoice.pdf")
        blobs = pbm._message_attachment_blobs(
            msg, mailbox="INBOX", uid="9", filename="invoice.pdf")
        assert [b.data for b in blobs] == [b"ONE", b"TWO"]

    def test_unknown_filename_raises(self):
        with pytest.raises(ValueError, match="not found"):
            pbm._message_attachment_blobs(
                _message_with_attachments(), mailbox="INBOX", uid="42",
                filename="nope.pdf")

    def test_out_of_range_index_raises(self):
        with pytest.raises(ValueError, match="index"):
            pbm._message_attachment_blobs(
                _message_with_attachments(), mailbox="INBOX", uid="42", index=9)

    def test_message_without_attachments_raises(self):
        msg = EmailMessage()
        msg.set_content("nothing here")
        with pytest.raises(ValueError, match="no attachments"):
            pbm._message_attachment_blobs(msg, mailbox="INBOX", uid="1")

    def test_unnamed_attachment_gets_indexed_fallback_name(self):
        msg = EmailMessage()
        msg.set_content("body")
        msg.add_attachment(b"RAW", maintype="application", subtype="octet-stream")
        blobs = pbm._message_attachment_blobs(msg, mailbox="INBOX", uid="3")
        assert blobs[0].filename == "attachment-1.bin"


class TestLocalAttachmentBlob:
    def test_reads_regular_file(self, tmp_path):
        f = tmp_path / "notes.txt"
        f.write_bytes(b"hello")
        blob = pbm._local_attachment_blob(str(f))
        assert blob.data == b"hello"
        assert blob.filename == "notes.txt"
        assert (blob.maintype, blob.subtype) == ("text", "plain")
        assert blob.origin == f"file:{f.resolve()}"

    def test_relative_path_refused(self):
        with pytest.raises(ValueError, match="absolute"):
            pbm._local_attachment_blob("notes.txt")

    def test_missing_file_refused(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            pbm._local_attachment_blob(str(tmp_path / "nope.txt"))

    def test_directory_refused(self, tmp_path):
        with pytest.raises(ValueError, match="regular file"):
            pbm._local_attachment_blob(str(tmp_path))

    def test_oversize_file_refused(self, tmp_path, monkeypatch):
        monkeypatch.setattr(pbm, "MAX_ATTACHMENT_BYTES", 4)
        f = tmp_path / "big.bin"
        f.write_bytes(b"12345")
        with pytest.raises(ValueError, match="over the"):
            pbm._local_attachment_blob(str(f))

    def test_allowlist_permits_path_inside_root(self, tmp_path, monkeypatch):
        allowed = tmp_path / "outbox"
        allowed.mkdir()
        f = allowed / "ok.txt"
        f.write_bytes(b"ok")
        monkeypatch.setattr(pbm, "ATTACHMENT_ROOTS", [allowed])
        assert pbm._local_attachment_blob(str(f)).data == b"ok"

    def test_allowlist_refuses_path_outside_root(self, tmp_path, monkeypatch):
        allowed = tmp_path / "outbox"
        allowed.mkdir()
        secret = tmp_path / "secret.txt"
        secret.write_bytes(b"s3cret")
        monkeypatch.setattr(pbm, "ATTACHMENT_ROOTS", [allowed])
        with pytest.raises(PermissionError, match="ATTACHMENT_ROOTS"):
            pbm._local_attachment_blob(str(secret))

    def test_symlink_out_of_allowed_root_refused(self, tmp_path, monkeypatch):
        # The allowlist check runs on the *resolved* path, so a symlink
        # planted inside an allowed root cannot smuggle a file out of it.
        allowed = tmp_path / "outbox"
        allowed.mkdir()
        secret = tmp_path / "secret.txt"
        secret.write_bytes(b"s3cret")
        link = allowed / "innocent.txt"
        link.symlink_to(secret)
        monkeypatch.setattr(pbm, "ATTACHMENT_ROOTS", [allowed])
        with pytest.raises(PermissionError, match="ATTACHMENT_ROOTS"):
            pbm._local_attachment_blob(str(link))


class TestAttachmentBudget:
    def _blob(self, size):
        return pbm._AttachmentBlob(filename="x.bin", maintype="application",
                                   subtype="octet-stream", data=b"x" * size,
                                   origin="test")

    def test_within_budget_passes(self):
        pbm._enforce_attachment_budget([self._blob(10), self._blob(10)])

    def test_too_many_attachments_refused(self, monkeypatch):
        monkeypatch.setattr(pbm, "MAX_ATTACHMENT_COUNT", 2)
        with pytest.raises(ValueError, match="exceeds the limit"):
            pbm._enforce_attachment_budget([self._blob(1)] * 3)

    def test_total_size_refused_even_when_each_file_fits(self, monkeypatch):
        monkeypatch.setattr(pbm, "MAX_ATTACHMENT_BYTES", 10)
        with pytest.raises(ValueError, match="total"):
            pbm._enforce_attachment_budget([self._blob(6), self._blob(6)])

    def test_empty_list_passes(self):
        pbm._enforce_attachment_budget([])


class TestBuildEmailWithAttachments:
    def test_attachments_appear_as_mixed_parts(self):
        blobs = pbm._message_attachment_blobs(
            _message_with_attachments(), mailbox="INBOX", uid="42")
        msg = pbm._build_email(
            sender="me@example.com", to=["bob@example.com"], subject="s",
            body_text="body", body_html=None, cc=None, bcc=None,
            reply_to_message_id=None, attachments=blobs)
        assert msg.get_content_type() == "multipart/mixed"
        names = [p.get_filename() for p in msg.walk() if p.get_filename()]
        assert names == ["report.pdf", "data.csv"]

    def test_html_alternative_survives_attachment(self):
        blob = pbm._AttachmentBlob(filename="a.txt", maintype="text",
                                   subtype="plain", data=b"hi", origin="test")
        msg = pbm._build_email(
            sender="me@example.com", to=["bob@example.com"], subject="s",
            body_text="plain body", body_html="<p>html body</p>", cc=None,
            bcc=None, reply_to_message_id=None, attachments=[blob])
        types = [p.get_content_type() for p in msg.walk()]
        assert "multipart/alternative" in types
        assert types[0] == "multipart/mixed"

    def test_payload_round_trips_byte_exact(self):
        raw = bytes(range(256))
        blob = pbm._AttachmentBlob(filename="b.bin", maintype="application",
                                   subtype="octet-stream", data=raw, origin="test")
        msg = pbm._build_email(
            sender="me@example.com", to=["bob@example.com"], subject="s",
            body_text="body", body_html=None, cc=None, bcc=None,
            reply_to_message_id=None, attachments=[blob])
        reparsed = email.message_from_bytes(msg.as_bytes())
        got = [p.get_payload(decode=True) for p in reparsed.walk()
               if p.get_filename() == "b.bin"]
        assert got == [raw]

    def test_no_attachments_leaves_message_shape_unchanged(self):
        msg = pbm._build_email(
            sender="me@example.com", to=["bob@example.com"], subject="s",
            body_text="body", body_html=None, cc=None, bcc=None,
            reply_to_message_id=None, attachments=[])
        assert msg.get_content_type() == "text/plain"


# ----------------------------------------------------------------------------
# Forward helpers
# ----------------------------------------------------------------------------
class TestForwardSubject:
    def test_prefix_added(self):
        assert pbm._forward_subject("Quarterly report") == "Fwd: Quarterly report"

    def test_existing_prefix_not_stacked(self):
        assert pbm._forward_subject("Fwd: Quarterly report") == "Fwd: Quarterly report"
        assert pbm._forward_subject("FW: Quarterly report") == "FW: Quarterly report"

    def test_empty_subject(self):
        assert pbm._forward_subject("") == "Fwd: (no subject)"
        assert pbm._forward_subject("   ") == "Fwd: (no subject)"


class TestForwardBodies:
    def test_attribution_block_and_original_body(self):
        text, html = pbm._forward_bodies(_message_with_attachments(), None)
        assert "---------- Forwarded message ----------" in text
        assert "From: Alice <alice@example.com>" in text
        assert "Subject: Quarterly report" in text
        assert "Please see the attached." in text
        assert html is not None

    def test_comment_precedes_the_forwarded_message(self):
        text, html = pbm._forward_bodies(_message_with_attachments(), "FYI")
        assert text.index("FYI") < text.index("Forwarded message")
        assert html.index("FYI") < html.index("Forwarded message")

    def test_html_attribution_is_escaped(self):
        # The attribution block is built from attacker-controlled headers; it
        # must not be able to inject markup into the HTML alternative.
        msg = EmailMessage()
        msg["From"] = '"<script>alert(1)</script>" <a@b.com>'
        msg["Subject"] = "hi"
        msg.set_content("plain")
        msg.add_alternative("<p>rich</p>", subtype="html")
        _, html = pbm._forward_bodies(msg, None)
        assert "<script>" not in html
        assert "&lt;script&gt;" in html

    def test_no_html_original_yields_no_html_forward(self):
        msg = EmailMessage()
        msg["Subject"] = "plain only"
        msg.set_content("just text")
        text, html = pbm._forward_bodies(msg, None)
        assert html is None
        assert "just text" in text

    def test_forwarded_body_is_not_wrapped_as_untrusted(self):
        # The wrapper is for content going *to the model*; a forward goes to a
        # human recipient and must not carry the delimiters.
        text, _ = pbm._forward_bodies(_message_with_attachments(), None)
        assert "UNTRUSTED_EMAIL_BODY" not in text


class TestHtmlEscape:
    def test_escapes_the_five_dangerous_characters(self):
        assert pbm._html_escape('<a href="x">&</a>') == (
            "&lt;a href=&quot;x&quot;&gt;&amp;&lt;/a&gt;")

    def test_ampersand_escaped_first(self):
        assert pbm._html_escape("&lt;") == "&amp;lt;"


# ----------------------------------------------------------------------------
# _extract_body_parts (verbatim) vs _extract_body (model-facing)
# ----------------------------------------------------------------------------
class TestExtractBodyParts:
    def test_verbatim_form_is_not_truncated(self):
        big = "x" * (pbm.MAX_BODY_CHARS + 5000)
        msg = EmailMessage()
        msg.set_content(big)
        plain, _, _ = pbm._extract_body_parts(msg)
        assert len(plain) > pbm.MAX_BODY_CHARS
        assert len(pbm._extract_body(msg)[0]) <= pbm.MAX_BODY_CHARS

    def test_verbatim_form_keeps_invisible_unicode(self):
        # Forwarded mail must reach its recipient as the sender wrote it; the
        # stripping is a model-facing defence, not a rewrite of the message.
        msg = EmailMessage()
        msg.set_content("he\u200bllo")
        assert "\u200b" in pbm._extract_body_parts(msg)[0]
        assert "\u200b" not in pbm._extract_body(msg)[0]

    def test_attachment_metadata_carries_index(self):
        _, _, attachments = pbm._extract_body(_message_with_attachments())
        assert [a["index"] for a in attachments] == [1, 2]

    def test_attachment_payload_still_excluded_from_body(self):
        plain, html, _ = pbm._extract_body_parts(_message_with_attachments())
        assert "PDFBYTES" not in plain
        assert "PDFBYTES" not in html


# ----------------------------------------------------------------------------
# Attachment-carrying inputs and their acknowledgement gates
# ----------------------------------------------------------------------------
class _StubContext:
    """Minimal stand-in for FastMCP's Context. Records what the tool logged
    so the refusal paths can be asserted without a live server."""

    def __init__(self):
        self.infos = []
        self.warnings = []

    async def info(self, message, *a, **kw):
        self.infos.append(message)

    async def warning(self, message, *a, **kw):
        self.warnings.append(message)


class TestForwardAttachmentRef:
    def test_defaults_to_inbox_and_all_attachments(self):
        ref = pbm.ForwardAttachmentRef(uid="42")
        assert ref.mailbox == "INBOX"
        assert ref.filename is None and ref.index is None

    def test_index_is_one_based(self):
        with pytest.raises(ValidationError):
            pbm.ForwardAttachmentRef(uid="42", index=0)

    def test_extra_fields_forbidden(self):
        with pytest.raises(ValidationError):
            pbm.ForwardAttachmentRef(uid="42", path="/etc/passwd")


class TestAttachmentInputLimits:
    def test_send_rejects_more_refs_than_the_count_cap(self):
        with pytest.raises(ValidationError):
            pbm.SendEmailInput(
                to=["a@b.com"], subject="s", body_text="b", acknowledged=True,
                attachments=[f"/tmp/f{i}" for i in range(pbm.MAX_ATTACHMENT_COUNT + 1)],
            )

    def test_send_accepts_attachments_and_forward_refs_together(self):
        params = pbm.SendEmailInput(
            to=["a@b.com"], subject="s", body_text="b", acknowledged=True,
            attachments=["/tmp/one.txt"],
            forward_attachments=[{"uid": "42", "filename": "report.pdf"}],
        )
        assert params.attachments == ["/tmp/one.txt"]
        assert params.forward_attachments[0].uid == "42"

    def test_attachments_default_to_none(self):
        params = pbm.SendEmailInput(
            to=["a@b.com"], subject="s", body_text="b", acknowledged=True)
        assert params.attachments is None
        assert params.forward_attachments is None


class TestForwardEmailInputRequiresAck:
    def test_missing_acknowledged_rejected(self):
        with pytest.raises(ValidationError):
            pbm.ForwardEmailInput(uid="42", to=["a@b.com"])

    def test_empty_recipient_list_rejected(self):
        with pytest.raises(ValidationError):
            pbm.ForwardEmailInput(uid="42", to=[], acknowledged=True)

    def test_defaults(self):
        params = pbm.ForwardEmailInput(uid="42", to=["a@b.com"], acknowledged=True)
        assert params.mailbox == "INBOX"
        assert params.include_attachments is True
        assert params.as_attachment is False
        assert params.save_to_sent is True
        assert params.subject is None


class TestForwardRefusedWithoutAck:
    def test_refusal_payload_and_warning(self):
        ctx = _StubContext()
        params = pbm.ForwardEmailInput(uid="42", to=["a@b.com"], acknowledged=False)
        data = json.loads(asyncio.run(pbm.proton_forward_email(params, ctx)))
        assert data["status"] == "refused"
        assert data["reason"] == "acknowledged_required"
        assert data["action"] == "proton_forward_email"
        assert ctx.warnings and "acknowledged=false" in ctx.warnings[0]

    def test_refusal_shape_from_helper(self):
        data = json.loads(pbm._refused_unack("proton_forward_email"))
        assert data["action"] == "proton_forward_email"
        assert data["status"] == "refused"


class TestDraftAttachmentGate:
    """A draft carrying attachments needs acknowledgement even when it is
    addressed only to the operator: reading a local file into a message is a
    side effect outside the model's sandbox, and the draft is one click from
    being sent."""

    def _self_draft(self, **extra):
        return pbm.CreateDraftInput(
            to=[pbm.BRIDGE_USER or "me@example.com"], subject="s",
            body_text="b", acknowledged=False, **extra)

    def test_self_draft_with_local_attachment_refused(self, monkeypatch):
        monkeypatch.setattr(pbm, "BRIDGE_USER", "me@example.com")
        monkeypatch.setattr(pbm, "DEFAULT_FROM", "me@example.com")
        ctx = _StubContext()
        params = self._self_draft(attachments=["/etc/hosts"])
        data = json.loads(asyncio.run(pbm.proton_create_draft(params, ctx)))
        assert data["status"] == "refused"
        assert "attachments" in data["message"].lower()

    def test_self_draft_with_forwarded_attachment_refused(self, monkeypatch):
        monkeypatch.setattr(pbm, "BRIDGE_USER", "me@example.com")
        monkeypatch.setattr(pbm, "DEFAULT_FROM", "me@example.com")
        ctx = _StubContext()
        params = self._self_draft(forward_attachments=[{"uid": "42"}])
        data = json.loads(asyncio.run(pbm.proton_create_draft(params, ctx)))
        assert data["status"] == "refused"

    def test_refusal_detail_is_appended_not_substituted(self):
        data = json.loads(pbm._refused_unack("proton_create_draft", "Extra context."))
        assert "acknowledged=true" in data["message"]
        assert data["message"].endswith("Extra context.")

    def test_refusal_without_detail_unchanged(self):
        data = json.loads(pbm._refused_unack("proton_create_draft"))
        assert data["message"].endswith("acknowledged=true.")


class TestForwardEmailHappyPath:
    """The forward tool's orchestration, with the IMAP / SMTP / keychain seams
    stubbed. Nothing here opens a socket: `_imap_call`, `_smtp_deliver`,
    `_append_to_sent` and `_resolve_password` are the four seams, and each is
    replaced with a recorder."""

    def _install_stubs(self, monkeypatch, source_message):
        sent = {}

        async def fake_imap_call(fn, *a, **kw):
            return source_message.as_bytes()

        async def fake_smtp(msg, sender, rcpts, pw):
            sent["msg"] = msg
            sent["sender"] = sender
            sent["rcpts"] = rcpts

        async def fake_append(msg):
            return "Sent", "Appended to Sent"

        monkeypatch.setattr(pbm, "_imap_call", fake_imap_call)
        monkeypatch.setattr(pbm, "_smtp_deliver", fake_smtp)
        monkeypatch.setattr(pbm, "_append_to_sent", fake_append)
        monkeypatch.setattr(pbm, "_resolve_password", lambda: "pw")
        monkeypatch.setattr(pbm, "DEFAULT_FROM", "me@example.com")
        return sent

    def test_inline_forward_carries_body_and_attachments(self, monkeypatch):
        sent = self._install_stubs(monkeypatch, _message_with_attachments())
        params = pbm.ForwardEmailInput(
            uid="42", to=["bob@example.com"], comment="FYI", acknowledged=True)
        data = json.loads(asyncio.run(pbm.proton_forward_email(params, _StubContext())))

        assert data["status"] == "forwarded"
        assert data["mode"] == "inline"
        assert data["subject"] == "Fwd: Quarterly report"
        assert [a["filename"] for a in data["attachments"]] == ["report.pdf", "data.csv"]
        assert data["saved_to_sent"] is True

        msg = sent["msg"]
        assert sent["rcpts"] == ["bob@example.com"]
        # Thread lineage without claiming to be a reply.
        assert msg["References"] == "<abc@example.com>"
        assert msg["In-Reply-To"] is None
        body = msg.get_body(preferencelist=("plain",)).get_content()
        assert "FYI" in body and "Forwarded message" in body

    def test_attachment_selection_by_filename(self, monkeypatch):
        self._install_stubs(monkeypatch, _message_with_attachments())
        params = pbm.ForwardEmailInput(
            uid="42", to=["bob@example.com"], acknowledged=True,
            attachment_filenames=["report.pdf"])
        data = json.loads(asyncio.run(pbm.proton_forward_email(params, _StubContext())))
        assert [a["filename"] for a in data["attachments"]] == ["report.pdf"]

    def test_include_attachments_false_drops_them(self, monkeypatch):
        self._install_stubs(monkeypatch, _message_with_attachments())
        params = pbm.ForwardEmailInput(
            uid="42", to=["bob@example.com"], acknowledged=True,
            include_attachments=False)
        data = json.loads(asyncio.run(pbm.proton_forward_email(params, _StubContext())))
        assert data["attachments"] == []

    def test_as_attachment_mode_wraps_the_original_once(self, monkeypatch):
        sent = self._install_stubs(monkeypatch, _message_with_attachments())
        params = pbm.ForwardEmailInput(
            uid="42", to=["bob@example.com"], acknowledged=True, as_attachment=True)
        data = json.loads(asyncio.run(pbm.proton_forward_email(params, _StubContext())))

        assert data["mode"] == "rfc822_attachment"
        # The original travels whole, so its parts are not also re-attached.
        assert data["attachments"] == []
        types = [p.get_content_type() for p in sent["msg"].walk()]
        assert types.count("message/rfc822") == 1
        assert "Quarterly report.eml" in [
            p.get_filename() for p in sent["msg"].walk() if p.get_filename()]

    def test_rfc822_filename_keeps_its_extension_on_a_long_subject(self, monkeypatch):
        long_subject = EmailMessage()
        long_subject["From"] = "alice@example.com"
        long_subject["Subject"] = "very long subject " * 20
        long_subject.set_content("body")
        sent = self._install_stubs(monkeypatch, long_subject)
        params = pbm.ForwardEmailInput(
            uid="42", to=["bob@example.com"], acknowledged=True, as_attachment=True)
        asyncio.run(pbm.proton_forward_email(params, _StubContext()))
        name = [p.get_filename() for p in sent["msg"].walk() if p.get_filename()][0]
        assert name.endswith(".eml")
        assert len(name) <= 155

    def test_rfc822_forward_preserves_the_original_headers_verbatim(self, monkeypatch):
        # The nested message is parsed with refold_source="none" so an odd but
        # legal header survives byte-for-byte instead of being refolded (or
        # raising) on the way out.
        raw = (
            b"From: Alice <alice@example.com>\r\n"
            b"Subject: odd one\r\n"
            b"X-Weird:    a header   with  odd folding\r\n\tcontinued badly\r\n"
            b"Date: Mon, 09 Mar 2026 14:30:00 +0000\r\n"
            b"Content-Type: text/plain\r\n\r\nbody here\r\n"
        )
        sent = {}

        async def fake_imap_call(fn, *a, **kw):
            return raw

        async def fake_smtp(msg, sender, rcpts, pw):
            sent["msg"] = msg

        async def fake_append(msg):
            return "Sent", "Appended to Sent"

        monkeypatch.setattr(pbm, "_imap_call", fake_imap_call)
        monkeypatch.setattr(pbm, "_smtp_deliver", fake_smtp)
        monkeypatch.setattr(pbm, "_append_to_sent", fake_append)
        monkeypatch.setattr(pbm, "_resolve_password", lambda: "pw")
        monkeypatch.setattr(pbm, "DEFAULT_FROM", "me@example.com")

        params = pbm.ForwardEmailInput(
            uid="42", to=["bob@example.com"], acknowledged=True, as_attachment=True)
        asyncio.run(pbm.proton_forward_email(params, _StubContext()))
        out = sent["msg"].as_bytes()
        assert b"X-Weird" in out
        assert b"continued badly" in out

    def test_forward_of_message_without_attachments_succeeds(self, monkeypatch):
        plain = EmailMessage()
        plain["From"] = "alice@example.com"
        plain["Subject"] = "no attachments here"
        plain.set_content("just a note")
        self._install_stubs(monkeypatch, plain)
        params = pbm.ForwardEmailInput(
            uid="7", to=["bob@example.com"], acknowledged=True)
        data = json.loads(asyncio.run(pbm.proton_forward_email(params, _StubContext())))
        assert data["status"] == "forwarded"
        assert data["attachments"] == []

    def test_unknown_attachment_name_is_an_error_not_a_silent_send(self, monkeypatch):
        sent = self._install_stubs(monkeypatch, _message_with_attachments())
        params = pbm.ForwardEmailInput(
            uid="42", to=["bob@example.com"], acknowledged=True,
            attachment_filenames=["nope.pdf"])
        out = asyncio.run(pbm.proton_forward_email(params, _StubContext()))
        assert out.startswith("Error: ValueError")
        assert "msg" not in sent  # nothing went out

    def test_subject_override_used_verbatim(self, monkeypatch):
        self._install_stubs(monkeypatch, _message_with_attachments())
        params = pbm.ForwardEmailInput(
            uid="42", to=["bob@example.com"], acknowledged=True,
            subject="Please handle this")
        data = json.loads(asyncio.run(pbm.proton_forward_email(params, _StubContext())))
        assert data["subject"] == "Please handle this"

    def test_result_does_not_echo_the_forwarded_body(self, monkeypatch):
        # The forwarded content is untrusted and does not need to re-enter the
        # model's context; the tool reports metadata only.
        self._install_stubs(monkeypatch, _message_with_attachments())
        params = pbm.ForwardEmailInput(
            uid="42", to=["bob@example.com"], acknowledged=True)
        out = asyncio.run(pbm.proton_forward_email(params, _StubContext()))
        assert "Please see the attached." not in out


class TestResolveAttachments:
    """`_resolve_attachments` is the shared entry point behind
    `proton_send_email`, `proton_create_draft` and the local-file half of
    `proton_forward_email`. The IMAP seam is stubbed."""

    def test_local_and_message_sourced_attachments_combine(self, tmp_path, monkeypatch):
        async def fake_imap_call(fn, *a, **kw):
            return _message_with_attachments().as_bytes()
        monkeypatch.setattr(pbm, "_imap_call", fake_imap_call)

        local = tmp_path / "cover.txt"
        local.write_bytes(b"cover letter")
        refs = [pbm.ForwardAttachmentRef(uid="42", filename="report.pdf")]

        blobs = asyncio.run(pbm._resolve_attachments([str(local)], refs))
        assert [b.filename for b in blobs] == ["cover.txt", "report.pdf"]
        assert blobs[0].origin.startswith("file:")
        assert blobs[1].origin == "INBOX:uid=42:#1"

    def test_none_inputs_yield_no_attachments(self):
        assert asyncio.run(pbm._resolve_attachments(None, None)) == []

    def test_budget_applies_across_both_sources(self, tmp_path, monkeypatch):
        async def fake_imap_call(fn, *a, **kw):
            return _message_with_attachments().as_bytes()
        monkeypatch.setattr(pbm, "_imap_call", fake_imap_call)
        monkeypatch.setattr(pbm, "MAX_ATTACHMENT_BYTES", 12)

        local = tmp_path / "cover.txt"
        local.write_bytes(b"cover letter")  # 12 bytes: fits alone, not together
        refs = [pbm.ForwardAttachmentRef(uid="42", filename="report.pdf")]
        with pytest.raises(ValueError, match="total"):
            asyncio.run(pbm._resolve_attachments([str(local)], refs))


# ----------------------------------------------------------------------------
# _header_oneline
# ----------------------------------------------------------------------------
class TestHeaderOneline:
    def test_plain_value_unchanged(self):
        assert pbm._header_oneline("Quarterly report") == "Quarterly report"

    def test_folded_value_unfolded(self):
        # A long Subject arrives folded across lines; putting the folded value
        # back on an outgoing header raises in the stdlib.
        assert pbm._header_oneline("very long\n subject here") == "very long subject here"

    def test_crlf_injection_collapsed(self):
        assert pbm._header_oneline("subject\r\nBcc: evil@example.com") == (
            "subject Bcc: evil@example.com")

    def test_empty_and_none(self):
        assert pbm._header_oneline("") == ""
        assert pbm._header_oneline(None) == ""


class TestBuildEmailHeaderSafety:
    def test_folded_subject_does_not_raise(self):
        msg = pbm._build_email(
            sender="me@example.com", to=["bob@example.com"],
            subject="long\n folded subject", body_text="b", body_html=None,
            cc=None, bcc=None, reply_to_message_id=None)
        assert msg["Subject"] == "long folded subject"

    def test_crlf_in_subject_cannot_inject_a_header(self):
        msg = pbm._build_email(
            sender="me@example.com", to=["bob@example.com"],
            subject="hello\r\nBcc: evil@example.com", body_text="b",
            body_html=None, cc=None, bcc=None, reply_to_message_id=None)
        assert msg["Bcc"] is None
        assert "evil@example.com" in msg["Subject"]
