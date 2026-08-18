defmodule SecurityTxt.ValidatorTest do
  use ExUnit.Case, async: true

  alias SecurityTxt.Field
  alias SecurityTxt.Validator

  defp field(name, value, line) do
    %Field{name: name, value: value, line: line}
  end

  test "collects value errors in source line order" do
    fields = [
      field("Preferred-Languages", "en_US", 1),
      field("Policy", "http://example.com/policy", 2),
      field("Contact", "ftp://example.com/report", 3),
      field("Expires", "2027-02-29T00:00:00Z", 4)
    ]

    result = Validator.validate(fields, false, DateTime.utc_now())

    assert Enum.map(result.errors, & &1.code) == [
             "invalid_lang",
             "invalid_https_field",
             "invalid_contact_scheme",
             "invalid_expires"
           ]
  end

  test "adds cardinality errors after value errors" do
    fields = [
      field("Expires", "2099-01-01T00:00:00Z", 1),
      field("Expires", "2099-02-01T00:00:00Z", 2)
    ]

    result = Validator.validate(fields, false, DateTime.utc_now())

    assert Enum.map(result.errors, &Map.take(&1, [:code, :line])) == [
             %{code: "no_contact", line: nil},
             %{code: "multi_expires", line: 2}
           ]
  end

  test "does not flatten invalid Preferred-Languages but flattens valid ones" do
    fields = [
      field("Contact", "https://example.com/report", 1),
      field("Expires", "2099-01-01T00:00:00Z", 2),
      field("Preferred-Languages", "en_US", 3),
      field("Preferred-Languages", "en, fr-CA", 4)
    ]

    result = Validator.validate(fields, false, DateTime.utc_now())

    assert result.preferred_languages == ["en", "fr-CA"]

    assert Enum.map(result.errors, &Map.take(&1, [:code, :line])) == [
             %{code: "invalid_lang", line: 3},
             %{code: "multi_lang", line: 4}
           ]
  end

  test "emits long_expiry recommendation per long Expires field" do
    fields = [
      field("Contact", "https://example.com/report", 1),
      field("Expires", "2099-01-01T00:00:00Z", 2),
      field("Expires", "2099-06-01T00:00:00Z", 3)
    ]

    result = Validator.validate(fields, false, DateTime.utc_now())

    assert Enum.map(result.recommendations, &Map.take(&1, [:code, :line])) == [
             %{code: "long_expiry", line: 2},
             %{code: "long_expiry", line: 3},
             %{code: "not_signed", line: nil}
           ]
  end

  test "returns notifications for unknown fields in source order" do
    fields = [
      field("X-First", "one", 1),
      field("Contact", "https://example.com/report", 2),
      field("X-Second", "two", 3)
    ]

    result = Validator.validate(fields, false, DateTime.utc_now())

    assert Enum.map(result.notifications, &Map.take(&1, [:code, :line])) == [
             %{code: "unknown_field", line: 1},
             %{code: "unknown_field", line: 3}
           ]
  end
end
