defmodule SecurityTxt.UriTest do
  use ExUnit.Case, async: true

  alias SecurityTxt.Diagnostic
  alias SecurityTxt.Uri

  @valid_cases [
    {"Contact", "https://example.com/report"},
    {"Contact", "mailto:security@example.com"},
    {"Contact", "mailto:security%2Btriage@example.com"},
    {"Contact", "tel:+1-201-555-0123"},
    {"Encryption", "https://example.com/key.asc"},
    {"Encryption", "dns:0123456789abcdef.example.com"},
    {"Encryption", "openpgp4fpr:0123456789ABCDEF"},
    {"Acknowledgments", "https://example.com/thanks"},
    {"Canonical", "https://example.com/.well-known/security.txt"},
    {"CSAF", "https://example.com/provider-metadata.json"},
    {"Hiring", "https://example.com/jobs"},
    {"Policy", "https://example.com/policy"}
  ]

  for {name, value} <- @valid_cases do
    test "accepts #{name} value #{value}" do
      assert Uri.validate(unquote(name), unquote(value), 4) == nil
    end
  end

  @malformed_cases [
    {"Contact", "security@example.com"},
    {"Contact", "../report"},
    {"Contact", "mailto:security example.com"},
    {"Contact", "mailto:security\texample.com"},
    {"Contact", "mailto:security\u0000@example.com"},
    {"Contact", "mailto:security%example.com"},
    {"Contact", "mailto:security%2@example.com"},
    {"Contact", "mailto:security%GG@example.com"},
    {"Contact", "mailto:"},
    {"Contact", "tel:"},
    {"Encryption", "dns:"},
    {"Encryption", "openpgp4fpr:"},
    {"Contact", "https:example.com/report"},
    {"Policy", "https:///policy"},
    {"Policy", "https:////example.com/policy"},
    {"Policy", "https://\\example.com/policy"},
    {"CSAF", "https://:443/provider-metadata.json"}
  ]

  for {name, value} <- @malformed_cases do
    test "rejects malformed #{name} value #{inspect(value)} before scheme checks" do
      assert %Diagnostic{code: "invalid_uri", line: 9} =
               Uri.validate(unquote(name), unquote(value), 9)
    end
  end

  @forbidden_raw_character_cases [
    {"Contact", "mailto:a\\b@example.com"},
    {"Contact", "mailto:a<b@example.com"},
    {"Policy", "ftp://example.com\\policy"}
  ]

  for {name, value} <- @forbidden_raw_character_cases do
    test "rejects RFC-forbidden raw characters in #{name} value #{inspect(value)} before scheme checks" do
      assert %Diagnostic{code: "invalid_uri", line: 10} =
               Uri.validate(unquote(name), unquote(value), 10)
    end
  end

  @fragment_only_cases [
    {"Contact", "mailto:#fragment"},
    {"Contact", "tel:#fragment"},
    {"Encryption", "dns:#fragment"},
    {"Encryption", "openpgp4fpr:#fragment"}
  ]

  for {name, value} <- @fragment_only_cases do
    test "rejects fragment-only scheme-specific content in #{name} value #{value}" do
      assert %Diagnostic{code: "invalid_uri", line: 11} =
               Uri.validate(unquote(name), unquote(value), 11)
    end
  end

  @scheme_error_cases [
    {"Contact", "http://example.com", "invalid_contact_scheme"},
    {"Contact", "ftp://example.com/report", "invalid_contact_scheme"},
    {"Acknowledgments", "http://example.com/thanks", "invalid_https_field"},
    {"Canonical", "ftp://example.com/security.txt", "invalid_https_field"},
    {"CSAF", "http://example.com/provider-metadata.json", "invalid_https_field"},
    {"Hiring", "ftp://example.com/jobs", "invalid_https_field"},
    {"Policy", "http://example.com/policy", "invalid_https_field"},
    {"Encryption", "ftp://example.com/key.asc", "invalid_https_field"}
  ]

  for {name, value, code} <- @scheme_error_cases do
    test "reports the field-level scheme error for #{name} value #{value}" do
      assert %Diagnostic{code: unquote(code), line: 12} =
               Uri.validate(unquote(name), unquote(value), 12)
    end
  end

  test "compares field names and schemes ASCII case-insensitively" do
    assert Uri.validate("cOnTaCt", "MaIlTo:security@example.com", 2) == nil
    assert Uri.validate("pOlIcY", "HTTPS://example.com/policy", 3) == nil
    assert Uri.validate("eNcRyPtIoN", "DnS:key.example.com", 4) == nil
  end

  for name <- ["Expires", "Preferred-Languages", "X-Extension"] do
    test "does not validate non-URI field #{name}" do
      assert Uri.validate(unquote(name), "not a URI", 5) == nil
    end
  end

  test "uses one deterministic URI diagnostic per value" do
    assert %Diagnostic{code: "invalid_uri"} = Uri.validate("Contact", "security@example.com", 4)
    assert %Diagnostic{code: "invalid_contact_scheme"} = Uri.validate("Contact", "http://example.com", 4)
    assert %Diagnostic{code: "invalid_https_field"} = Uri.validate("Policy", "http://example.com/policy", 4)
    assert Uri.validate("CSAF", "https://example.com/provider-metadata.json", 4) == nil
  end
end
