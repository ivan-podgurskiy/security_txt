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
end
