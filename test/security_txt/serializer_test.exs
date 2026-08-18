defmodule SecurityTxt.SerializerTest do
  use ExUnit.Case, async: true

  @future "2099-01-01T00:00:00Z"

  defp required(overrides) do
    [
      contact: "https://example.com/report",
      expires: @future
    ]
    |> Keyword.merge(overrides)
  end

  describe "serialize/1" do
    test "serializes canonical field order" do
      output =
        SecurityTxt.serialize(
          comments: ["Security contact"],
          contact: ["mailto:a@example.com", "https://example.com/security"],
          expires: ~U[2030-01-01 00:00:00Z],
          csaf: "https://example.com/.well-known/csaf/provider-metadata.json",
          preferred_languages: ["en", "tr"]
        )

      assert output ==
               "# Security contact\n" <>
                 "Contact: mailto:a@example.com\n" <>
                 "Contact: https://example.com/security\n" <>
                 "Expires: 2030-01-01T00:00:00Z\n" <>
                 "CSAF: https://example.com/.well-known/csaf/provider-metadata.json\n" <>
                 "Preferred-Languages: en, tr\n"
    end

    test "serializes every field in canonical order with exactly one trailing LF" do
      output =
        SecurityTxt.serialize(
          comments: ["Security contact", "Managed by the security team"],
          contact: ["mailto:a@example.com", "https://example.com/security"],
          expires: ~U[2099-01-01 00:00:00Z],
          acknowledgments: [
            "https://example.com/thanks/first",
            "https://example.com/thanks/second"
          ],
          canonical: "https://example.com/.well-known/security.txt",
          csaf: "https://example.com/.well-known/csaf/provider-metadata.json",
          encryption: "openpgp4fpr:0123456789ABCDEF",
          hiring: "https://example.com/jobs",
          policy: "https://example.com/policy",
          preferred_languages: ["en", "tr"]
        )

      assert output ==
               "# Security contact\n" <>
                 "# Managed by the security team\n" <>
                 "Contact: mailto:a@example.com\n" <>
                 "Contact: https://example.com/security\n" <>
                 "Expires: 2099-01-01T00:00:00Z\n" <>
                 "Acknowledgments: https://example.com/thanks/first\n" <>
                 "Acknowledgments: https://example.com/thanks/second\n" <>
                 "Canonical: https://example.com/.well-known/security.txt\n" <>
                 "CSAF: https://example.com/.well-known/csaf/provider-metadata.json\n" <>
                 "Encryption: openpgp4fpr:0123456789ABCDEF\n" <>
                 "Hiring: https://example.com/jobs\n" <>
                 "Policy: https://example.com/policy\n" <>
                 "Preferred-Languages: en, tr\n"

      assert String.ends_with?(output, "\n")
      refute String.ends_with?(output, "\n\n")
    end

    test "normalizes scalar and array fields without reordering values" do
      assert SecurityTxt.serialize(
               contact: ["tel:+1-201-555-0123", "mailto:security@example.com"],
               expires: @future,
               policy: ["https://example.com/first", "https://example.com/second"],
               preferred_languages: "en-US"
             ) ==
               "Contact: tel:+1-201-555-0123\n" <>
                 "Contact: mailto:security@example.com\n" <>
                 "Expires: #{@future}\n" <>
                 "Policy: https://example.com/first\n" <>
                 "Policy: https://example.com/second\n" <>
                 "Preferred-Languages: en-US\n"
    end

    test "formats DateTime values in UTC, removing only zero milliseconds" do
      {:ok, offset_expiry, _} = DateTime.from_iso8601("2099-01-01T02:30:00.000+02:30")

      assert SecurityTxt.serialize(required(expires: offset_expiry)) =~
               "Expires: 2099-01-01T00:00:00Z\n"

      assert SecurityTxt.serialize(required(expires: ~U[2099-01-01 00:00:00.123456Z])) =~
               "Expires: 2099-01-01T00:00:00.123456Z\n"
    end

    test "preserves a valid string expiry representation" do
      assert SecurityTxt.serialize(required(expires: "2099-01-01t02:30:00.125+02:30")) =~
               "Expires: 2099-01-01t02:30:00.125+02:30\n"
    end

    for {name, overrides} <- [
          {"contact", [contact: []]},
          {"acknowledgments", [acknowledgments: []]},
          {"canonical", [canonical: []]},
          {"csaf", [csaf: []]},
          {"encryption", [encryption: []]},
          {"hiring", [hiring: []]},
          {"policy", [policy: []]},
          {"preferred_languages", [preferred_languages: []]},
          {"comments", [comments: []]}
        ] do
      test "rejects an empty #{name} array" do
        assert_raise ArgumentError, fn ->
          SecurityTxt.serialize(required(unquote(overrides)))
        end
      end
    end

    test "rejects missing required Contact or Expires" do
      assert_raise ArgumentError, fn ->
        SecurityTxt.serialize(expires: @future)
      end

      assert_raise ArgumentError, fn ->
        SecurityTxt.serialize(contact: "https://example.com/report")
      end
    end

    for {name, overrides} <- [
          {"comments", [comments: ["safe\nContact: tel:injected"]]},
          {"contact", [contact: "mailto:a@example.com\rExpires: injected"]},
          {"expires", [expires: "#{@future}\nPolicy: injected"]},
          {"acknowledgments", [acknowledgments: "https://example.com/a\r"]},
          {"canonical", [canonical: "https://example.com/a\n"]},
          {"csaf", [csaf: "https://example.com/a\r"]},
          {"encryption", [encryption: "dns:key.example.com\n"]},
          {"hiring", [hiring: "https://example.com/jobs\r"]},
          {"policy", [policy: "https://example.com/policy\n"]},
          {"preferred_languages", [preferred_languages: "en\r"]}
        ] do
      test "rejects CR or LF injection in #{name}" do
        assert_raise ArgumentError, fn ->
          SecurityTxt.serialize(required(unquote(overrides)))
        end
      end
    end

    for {name, overrides} <- [
          {"contact URI", [contact: "ftp://example.com/report"]},
          {"contact syntax", [contact: "mailto:a\\b@example.com"]},
          {"acknowledgments URI", [acknowledgments: "http://example.com/thanks"]},
          {"canonical URI", [canonical: "ftp://example.com/security.txt"]},
          {"CSAF URI", [csaf: "http://example.com/provider.json"]},
          {"encryption URI", [encryption: "ftp://example.com/key"]},
          {"hiring URI", [hiring: "../jobs"]},
          {"policy URI", [policy: "http://example.com/policy"]},
          {"language tag", [preferred_languages: "en_US"]},
          {"language list as one tag", [preferred_languages: "en, fr"]},
          {"timestamp syntax", [expires: "2099-02-30T00:00:00Z"]},
          {"expired timestamp", [expires: "2000-01-01T00:00:00Z"]}
        ] do
      test "rejects invalid #{name}" do
        assert_raise ArgumentError, fn ->
          SecurityTxt.serialize(required(unquote(overrides)))
        end
      end
    end

    test "rejects invalid DateTime expiry" do
      assert_raise ArgumentError, fn ->
        SecurityTxt.serialize(
          required(
            expires: %DateTime{
              calendar: Calendar.ISO,
              day: 1,
              hour: 0,
              microsecond: {0, 0},
              minute: 0,
              month: 1,
              second: 0,
              std_offset: 0,
              time_zone: "Etc/UTC",
              utc_offset: 0,
              year: 0,
              zone_abbr: "UTC"
            }
          )
        )
      end
    end

    test "rejects runtime option types that cannot serialize valid fields" do
      assert_raise ArgumentError, fn ->
        SecurityTxt.serialize(required(expires: [@future]))
      end

      assert_raise ArgumentError, fn ->
        SecurityTxt.serialize(required(contact: [42]))
      end

      assert_raise ArgumentError, fn ->
        SecurityTxt.serialize(required(comments: "note"))
      end
    end

    test "rejects unknown option keys" do
      assert_raise ArgumentError, fn ->
        SecurityTxt.serialize(required(unknown: "value"))
      end
    end

    test "rejects non-keyword list options at the serializer layer" do
      assert_raise ArgumentError, ~r/options must be a keyword list/, fn ->
        SecurityTxt.Serializer.serialize(%{})
      end
    end

    test "rejects non-string comment entries" do
      assert_raise ArgumentError, ~r/comments must contain only strings/, fn ->
        SecurityTxt.Serializer.serialize(required(comments: [1]))
      end
    end

    test "rejects non-string optional field value types" do
      assert_raise ArgumentError, ~r/Policy must be a string or non-empty array/, fn ->
        SecurityTxt.Serializer.serialize(required(policy: 42))
      end
    end

    test "rejects output that exceeds parser resource limits" do
      assert_raise ArgumentError, fn ->
        SecurityTxt.serialize(
          required(policy: "https://example.com/#{String.duplicate("x", 2_100)}")
        )
      end

      assert_raise ArgumentError, fn ->
        SecurityTxt.serialize(required(comments: [String.duplicate("x", 32_768)]))
      end

      assert_raise ArgumentError, fn ->
        SecurityTxt.serialize(required(comments: List.duplicate("x", 999)))
      end
    end

    test "allows long expiry timestamps during serialization" do
      output = SecurityTxt.serialize(required(expires: "2099-01-01T00:00:00Z"))

      assert output =~ "Expires: 2099-01-01T00:00:00Z\n"
    end

    test "always produces a document accepted by parse for valid options" do
      output =
        SecurityTxt.serialize(
          contact: ["mailto:security@example.com", "https://example.com/report"],
          expires: ~U[2099-01-01 00:00:00.456789Z],
          canonical: "https://example.com/.well-known/security.txt",
          csaf: "https://example.com/.well-known/csaf/provider-metadata.json",
          encryption: "dns:key.example.com",
          preferred_languages: ["en", "i-klingon", "x-acme"]
        )

      result = SecurityTxt.parse(output)

      assert result.valid
      assert result.errors == []

      assert result.contact == [
               "mailto:security@example.com",
               "https://example.com/report"
             ]

      assert result.preferred_languages == ["en", "i-klingon", "x-acme"]
    end
  end
end
