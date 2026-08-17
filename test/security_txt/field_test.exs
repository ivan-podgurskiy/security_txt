defmodule SecurityTxt.FieldTest do
  use ExUnit.Case, async: true

  alias SecurityTxt.Field

  test "stores name, value, and line" do
    field = %Field{name: "Contact", value: "mailto:sec@example.com", line: 1}

    assert field.name == "Contact"
    assert field.value == "mailto:sec@example.com"
    assert field.line == 1
  end

  test "to_map/1 returns the PRD map" do
    field = %Field{name: "Contact", value: "mailto:sec@example.com", line: 1}

    assert Field.to_map(field) == %{
             name: "Contact",
             value: "mailto:sec@example.com",
             line: 1
           }
  end

  test "collect/1 groups registered fields case-insensitively" do
    fields = [
      %Field{name: "cOnTaCt", value: "mailto:first@example.com", line: 1},
      %Field{name: "EXPIRES", value: "2026-01-01T00:00:00Z", line: 2},
      %Field{name: "expires", value: "2027-01-01T00:00:00Z", line: 3},
      %Field{name: "Acknowledgments", value: "https://example.com/acks", line: 4},
      %Field{name: "canonical", value: "https://example.com/.well-known/security.txt", line: 5},
      %Field{name: "CSAF", value: "https://example.com/csaf", line: 6},
      %Field{name: "encryption", value: "https://example.com/pgp-key.txt", line: 7},
      %Field{name: "HIRING", value: "https://example.com/jobs", line: 8},
      %Field{name: "Policy", value: "https://example.com/policy", line: 9},
      %Field{name: "preferred-languages", value: "en, de", line: 10},
      %Field{name: "Contact", value: "mailto:second@example.com", line: 11},
      %Field{name: "X-Custom", value: "ignored", line: 12}
    ]

    assert Field.collect(fields) == %{
             contact: ["mailto:first@example.com", "mailto:second@example.com"],
             expires: "2026-01-01T00:00:00Z",
             acknowledgments: ["https://example.com/acks"],
             canonical: ["https://example.com/.well-known/security.txt"],
             csaf: ["https://example.com/csaf"],
             encryption: ["https://example.com/pgp-key.txt"],
             hiring: ["https://example.com/jobs"],
             policy: ["https://example.com/policy"],
             preferred_languages: ["en, de"]
           }
  end

  test "collect/1 returns nil expires when absent" do
    assert Field.collect([]) == %{
             contact: [],
             expires: nil,
             acknowledgments: [],
             canonical: [],
             csaf: [],
             encryption: [],
             hiring: [],
             policy: [],
             preferred_languages: []
           }
  end
end
