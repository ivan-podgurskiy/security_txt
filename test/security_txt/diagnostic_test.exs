defmodule SecurityTxt.DiagnosticTest do
  use ExUnit.Case, async: true

  alias SecurityTxt.Diagnostic

  test "creates a stable document-level diagnostic" do
    assert Diagnostic.new(:no_contact, nil) == %Diagnostic{
             code: "no_contact",
             message: "At least one Contact field is required.",
             line: nil
           }
  end

  test "preserves one-based source lines" do
    assert %Diagnostic{code: "invalid_uri", line: 7} = Diagnostic.new(:invalid_uri, 7)
  end

  test "to_map/1 returns the PRD map" do
    diagnostic = Diagnostic.new(:no_contact, nil)

    assert Diagnostic.to_map(diagnostic) == %{
             code: "no_contact",
             message: "At least one Contact field is required.",
             line: nil
           }
  end
end
