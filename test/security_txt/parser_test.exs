defmodule SecurityTxt.ParserTest do
  use ExUnit.Case, async: true

  alias SecurityTxt.Diagnostic
  alias SecurityTxt.Field
  alias SecurityTxt.Parser

  defp line(number, text), do: %{number: number, text: text}

  test "ignores blank lines" do
    assert {[], []} =
             Parser.parse_lines([
               line(1, ""),
               line(2, "   "),
               line(3, "\t")
             ])
  end

  test "ignores column-one comments" do
    assert {[], []} =
             Parser.parse_lines([
               line(1, "# this is a comment"),
               line(2, "#Contact: ignored")
             ])
  end

  test "does not treat leading whitespace before # as a comment" do
    assert {[], [%Diagnostic{code: "invalid_line", line: 1}]} =
             Parser.parse_lines([line(1, "  # not a comment")])
  end

  test "ignores comments longer than 2048 characters" do
    comment = "#" <> String.duplicate("x", 2048)

    assert {[], []} = Parser.parse_lines([line(1, comment)])
  end

  test "preserves spelling and collects registered names case-insensitively" do
    assert {[%Field{name: "cOnTaCt", value: "mailto:a@example.com", line: 3}], []} =
             Parser.parse_lines([line(3, "cOnTaCt:  mailto:a@example.com  ")])
  end

  test "parses all nine registered field names" do
    lines = [
      line(1, "Contact: mailto:a@example.com"),
      line(2, "Expires: 2026-12-31T23:59:59Z"),
      line(3, "Acknowledgments: https://example.com/acks"),
      line(4, "Canonical: https://example.com/.well-known/security.txt"),
      line(5, "CSAF: https://example.com/csaf"),
      line(6, "Encryption: https://example.com/pgp-key.txt"),
      line(7, "Hiring: https://example.com/jobs"),
      line(8, "Policy: https://example.com/policy"),
      line(9, "Preferred-Languages: en, de")
    ]

    assert {fields, []} = Parser.parse_lines(lines)
    assert Enum.map(fields, & &1.name) == [
             "Contact",
             "Expires",
             "Acknowledgments",
             "Canonical",
             "CSAF",
             "Encryption",
             "Hiring",
             "Policy",
             "Preferred-Languages"
           ]
  end

  test "preserves contact field order" do
    lines = [
      line(1, "Contact: mailto:first@example.com"),
      line(2, "Contact: mailto:second@example.com"),
      line(3, "Contact: https://example.com/contact")
    ]

    assert {fields, []} = Parser.parse_lines(lines)

    assert Enum.map(fields, & &1.value) == [
             "mailto:first@example.com",
             "mailto:second@example.com",
             "https://example.com/contact"
           ]
  end

  test "treats # inside a value as part of the value" do
    assert {[%Field{name: "Contact", value: "https://example.com/a#fragment", line: 1}], []} =
             Parser.parse_lines([line(1, "Contact: https://example.com/a#fragment")])
  end

  test "rejects empty values with invalid_line" do
    assert {[], [%Diagnostic{code: "invalid_line", line: 2}]} =
             Parser.parse_lines([line(2, "Contact:")])

    assert {[], [%Diagnostic{code: "invalid_line", line: 3}]} =
             Parser.parse_lines([line(3, "Contact:   ")])
  end

  test "rejects lines without a colon with invalid_line" do
    assert {[], [%Diagnostic{code: "invalid_line", line: 4}]} =
             Parser.parse_lines([line(4, "Contact mailto:a@example.com")])
  end

  test "rejects invalid field names with invalid_line" do
    assert {[], [%Diagnostic{code: "invalid_line", line: 5}]} =
             Parser.parse_lines([line(5, "Contact : mailto:a@example.com")])

    assert {[], [%Diagnostic{code: "invalid_line", line: 6}]} =
             Parser.parse_lines([line(6, ":mailto:a@example.com")])
  end

  test "keeps unknown syntactically valid fields without errors" do
    assert {[%Field{name: "X-Custom", value: "value", line: 1}], []} =
             Parser.parse_lines([line(1, "X-Custom: value")])
  end

  test "accepts a registered field line of exactly 2048 characters" do
    # "Contact: " is 9 chars; value must be 2039 chars for total 2048
    value = String.duplicate("a", 2039)
    text = "Contact: " <> value

    assert String.length(text) == 2048

    assert {[%Field{name: "Contact", value: ^value, line: 1}], []} =
             Parser.parse_lines([line(1, text)])
  end

  test "rejects a registered field line longer than 2048 characters" do
    value = String.duplicate("a", 2040)
    text = "Contact: " <> value

    assert String.length(text) == 2049

    assert {[], [%Diagnostic{code: "field_too_long", line: 2}]} =
             Parser.parse_lines([line(2, text)])
  end

  test "does not reject unknown fields longer than 2048 characters" do
    value = String.duplicate("a", 2039)
    text = "X-Custom: " <> value

    assert String.length(text) == 2049

    assert {[%Field{name: "X-Custom", value: ^value, line: 1}], []} =
             Parser.parse_lines([line(1, text)])
  end
end
