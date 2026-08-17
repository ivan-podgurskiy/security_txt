defmodule SecurityTxtTest do
  use ExUnit.Case, async: true

  doctest SecurityTxt

  defp future_timestamp(months \\ 1) do
    DateTime.utc_now()
    |> DateTime.add(months * 30 * 24 * 60 * 60, :second)
    |> DateTime.to_iso8601()
  end

  defp signed(body) do
    lines =
      body
      |> String.trim_trailing()
      |> String.split("\n")

    [
      "-----BEGIN PGP SIGNED MESSAGE-----",
      "Hash: SHA256",
      "",
      lines,
      "-----BEGIN PGP SIGNATURE-----",
      "placeholder",
      "-----END PGP SIGNATURE-----",
      ""
    ]
    |> List.flatten()
    |> Enum.join("\n")
  end

  test "exports the package version through Mix metadata" do
    assert Mix.Project.config()[:app] == :security_txt
    assert Mix.Project.config()[:version] == "1.0.0"
  end

  test "parses a fully valid signed document with every convenience accessor" do
    expires = future_timestamp()
    content =
      signed(
        "Contact: mailto:security@example.com\n" <>
          "Contact: https://example.com/report\n" <>
          "Expires: #{expires}\n" <>
          "Acknowledgments: https://example.com/thanks\n" <>
          "Canonical: https://example.com/.well-known/security.txt\n" <>
          "CSAF: https://example.com/.well-known/csaf/provider-metadata.json\n" <>
          "Encryption: openpgp4fpr:0123456789ABCDEF\n" <>
          "Hiring: https://example.com/jobs\n" <>
          "Policy: https://example.com/policy\n" <>
          "Preferred-Languages: en, fr-CA"
      )

    result = SecurityTxt.parse(content)

    assert result.valid
    assert result.contact == [
             "mailto:security@example.com",
             "https://example.com/report"
           ]
    assert result.expires == expires
    assert result.acknowledgments == ["https://example.com/thanks"]
    assert result.canonical == ["https://example.com/.well-known/security.txt"]
    assert result.csaf == ["https://example.com/.well-known/csaf/provider-metadata.json"]
    assert result.encryption == ["openpgp4fpr:0123456789ABCDEF"]
    assert result.hiring == ["https://example.com/jobs"]
    assert result.policy == ["https://example.com/policy"]
    assert result.preferred_languages == ["en", "fr-CA"]
    assert result.signed
    assert result.errors == []
    assert result.recommendations == []
    assert result.notifications == []

    assert Enum.at(result.fields, 0) == %{
             name: "Contact",
             value: "mailto:security@example.com",
             line: 4
           }
  end

  test "reports both required fields for empty input" do
    result = SecurityTxt.parse("")

    assert result.valid == false
    assert result.fields == []
    assert Enum.map(result.errors, &Map.take(&1, [:code, :line])) == [
             %{code: "no_contact", line: nil},
             %{code: "no_expires", line: nil}
           ]
    assert Enum.map(result.recommendations, & &1.code) == ["not_signed"]
  end

  test "reports both required fields for comment-only input" do
    result = SecurityTxt.parse("# only a comment\n")

    assert result.valid == false
    assert result.fields == []
    assert Enum.map(result.errors, &Map.take(&1, [:code, :line])) == [
             %{code: "no_contact", line: nil},
             %{code: "no_expires", line: nil}
           ]
    assert Enum.map(result.recommendations, & &1.code) == ["not_signed"]
  end

  test "reports missing and duplicate required fields in cardinality order" do
    result =
      SecurityTxt.parse(
        "Expires: #{future_timestamp()}\nExpires: #{future_timestamp(2)}\n"
      )

    assert Enum.map(result.errors, &Map.take(&1, [:code, :line])) == [
             %{code: "no_contact", line: nil},
             %{code: "multi_expires", line: 2}
           ]
  end

  test "validates URI, expiry, and language values in source-line order" do
    result =
      SecurityTxt.parse(
        "Preferred-Languages: en_US\n" <>
          "Policy: http://example.com/policy\n" <>
          "Contact: ftp://example.com/report\n" <>
          "Expires: 2027-02-29T00:00:00Z\n"
      )

    assert Enum.map(result.errors, &Map.take(&1, [:code, :line])) == [
             %{code: "invalid_lang", line: 1},
             %{code: "invalid_https_field", line: 2},
             %{code: "invalid_contact_scheme", line: 3},
             %{code: "invalid_expires", line: 4}
           ]
  end

  test "reports expired timestamps as value errors" do
    result =
      SecurityTxt.parse(
        "Contact: https://example.com/report\nExpires: 2000-01-01T00:00:00Z\n"
      )

    assert Enum.map(result.errors, &Map.take(&1, [:code, :line])) == [
             %{code: "expired", line: 2}
           ]
  end

  test "returns ordered severity lists and public maps" do
    result =
      SecurityTxt.parse(
        "X-Example: value\nContact: mailto:a@example.com\nExpires: 2099-01-01T00:00:00Z\n"
      )

    assert result.valid
    assert Enum.map(result.recommendations, & &1.code) == [
             "long_expiry",
             "no_encryption",
             "not_signed"
           ]
    assert [%{code: "unknown_field", line: 1}] =
             Enum.map(result.notifications, &Map.take(&1, [:code, :line]))
  end

  test "returns recommendations in their specified order" do
    result =
      SecurityTxt.parse(
        "Contact: mailto:a@example.com\n" <>
          "Expires: 2099-01-01T00:00:00Z\n" <>
          "CSAF: https://example.com/one.json\n" <>
          "CSAF: https://example.com/two.json\n"
      )

    assert result.valid
    assert Enum.map(result.recommendations, &Map.take(&1, [:code, :line])) == [
             %{code: "long_expiry", line: 2},
             %{code: "no_encryption", line: nil},
             %{code: "not_signed", line: nil},
             %{code: "multi_csaf", line: 4}
           ]
  end

  test "recommends Canonical only for signed input" do
    result =
      SecurityTxt.parse(
        signed(
          "Contact: https://example.com/report\nExpires: #{future_timestamp()}"
        )
      )

    assert Enum.map(result.recommendations, & &1.code) == ["no_canonical"]
  end

  test "keeps unknown fields and reports notifications by line" do
    result =
      SecurityTxt.parse(
        "X-First: one\n" <>
          "cOnTaCt: https://example.com/report\n" <>
          "eXpIrEs: #{future_timestamp()}\n" <>
          "X-Second: two\n"
      )

    assert result.valid
    assert Enum.map(result.fields, & &1.name) == ["X-First", "cOnTaCt", "eXpIrEs", "X-Second"]
    assert Enum.map(result.notifications, &Map.take(&1, [:code, :line])) == [
             %{code: "unknown_field", line: 1},
             %{code: "unknown_field", line: 4}
           ]
  end

  test "preserves physical line numbers through a signed envelope" do
    result =
      SecurityTxt.parse(
        signed(
          "# body\nContact: not-a-uri\nExpires: #{future_timestamp()}\nPolicy: relative"
        )
      )

    assert Enum.map(result.errors, &Map.take(&1, [:code, :line])) == [
             %{code: "invalid_uri", line: 5},
             %{code: "invalid_uri", line: 7}
           ]
  end

  test "flattens repeated Preferred-Languages while reporting the duplicate" do
    result =
      SecurityTxt.parse(
        "Contact: https://example.com/report\n" <>
          "Expires: #{future_timestamp()}\n" <>
          "Preferred-Languages: en, fr-CA\n" <>
          "preferred-languages: i-klingon, x-acme\n"
      )

    assert result.preferred_languages == ["en", "fr-CA", "i-klingon", "x-acme"]
    assert Enum.map(result.errors, &Map.take(&1, [:code, :line])) == [
             %{code: "multi_lang", line: 4}
           ]
  end

  test "orders physical, value, then cardinality errors" do
    result =
      SecurityTxt.parse(
        "\uFEFFPolicy: relative\nPreferred-Languages: en_US\nExpires: invalid\nExpires: invalid-again\n"
      )

    assert Enum.map(result.errors, &Map.take(&1, [:code, :line])) == [
             %{code: "bom_present", line: 1},
             %{code: "invalid_uri", line: 1},
             %{code: "invalid_lang", line: 2},
             %{code: "invalid_expires", line: 3},
             %{code: "invalid_expires", line: 4},
             %{code: "no_contact", line: nil},
             %{code: "multi_expires", line: 4}
           ]
  end

  test "short-circuits oversized input without parsing fields" do
    result =
      SecurityTxt.parse(
        "Contact: https://example.com/report\nExpires: #{future_timestamp()}\n" <>
          String.duplicate("x", 32_768)
      )

    assert result.valid == false
    assert result.fields == []
    assert result.contact == []
    assert result.expires == nil
    assert result.preferred_languages == []
    assert result.signed == false
    assert Enum.map(result.errors, &Map.take(&1, [:code, :line])) == [
             %{code: "file_too_large", line: nil}
           ]
    assert result.recommendations == []
    assert result.notifications == []
  end
end
