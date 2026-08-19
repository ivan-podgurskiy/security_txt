defmodule AcceptanceTest do
  use ExUnit.Case, async: true

  defp future_expires(years \\ 2) do
    DateTime.utc_now()
    |> DateTime.add(years * 365 * 24 * 60 * 60, :second)
    |> DateTime.to_iso8601()
  end

  describe "parse/1 quick start" do
    test "returns fields, accessors, and diagnostics for a valid document" do
      expires = future_expires()

      result =
        SecurityTxt.parse("""
        Contact: https://example.com/report
        Expires: #{expires}
        Policy: https://example.com/security-policy
        Preferred-Languages: en, tr
        """)

      assert result.valid
      assert result.contact == ["https://example.com/report"]
      assert result.policy == ["https://example.com/security-policy"]
      assert result.preferred_languages == ["en", "tr"]
      assert result.errors == []
      assert Enum.map(result.recommendations, & &1.code) == ["long_expiry", "not_signed"]
    end
  end

  describe "serialize/1" do
    test "emits canonical field order with LF endings and a trailing newline" do
      expires = future_expires()

      content =
        SecurityTxt.serialize(
          comments: ["Security contact for example.com"],
          contact: ["mailto:security@example.com", "https://example.com/report"],
          expires: expires,
          canonical: "https://example.com/.well-known/security.txt",
          csaf: "https://example.com/.well-known/csaf/provider-metadata.json",
          encryption: "openpgp4fpr:0123456789ABCDEF",
          policy: "https://example.com/security-policy",
          preferred_languages: ["en", "tr"]
        )

      assert content ==
               Enum.join(
                 [
                   "# Security contact for example.com",
                   "Contact: mailto:security@example.com",
                   "Contact: https://example.com/report",
                   "Expires: #{expires}",
                   "Canonical: https://example.com/.well-known/security.txt",
                   "CSAF: https://example.com/.well-known/csaf/provider-metadata.json",
                   "Encryption: openpgp4fpr:0123456789ABCDEF",
                   "Policy: https://example.com/security-policy",
                   "Preferred-Languages: en, tr",
                   ""
                 ],
                 "\n"
               )
    end
  end
end
