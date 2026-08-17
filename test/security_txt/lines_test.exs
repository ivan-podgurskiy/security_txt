defmodule SecurityTxt.LinesTest do
  use ExUnit.Case, async: true

  alias SecurityTxt.Diagnostic
  alias SecurityTxt.Lines

  test "empty input returns no lines or errors" do
    assert %{lines: [], errors: [], rejected: false} = Lines.scan("")
  end

  test "rejects input above the byte limit without parsing lines" do
    scan = Lines.scan(String.duplicate("é", 16_384) <> "\n")

    assert scan.rejected
    assert scan.lines == []
    assert Enum.map(scan.errors, & &1.code) == ["file_too_large"]
    assert [%Diagnostic{line: nil}] = scan.errors
  end

  test "accepts input at exactly the byte limit" do
    input = String.duplicate("a", 32_767) <> "\n"

    assert %{lines: lines, errors: [], rejected: false} = Lines.scan(input)
    assert byte_size(input) == 32_768
    assert length(lines) == 1
    assert hd(lines).text == String.duplicate("a", 32_767)
    assert hd(lines).number == 1
  end

  test "accepts mixed LF and CRLF" do
    assert %{errors: []} =
             Lines.scan("Contact: mailto:a@example.com\r\nExpires: 2030-01-01T00:00:00Z\n")
  end

  test "splits on LF and strips preceding CR for CRLF" do
    scan = Lines.scan("line one\r\nline two\n")

    assert [%{number: 1, text: "line one"}, %{number: 2, text: "line two"}] = scan.lines
    assert scan.errors == []
  end

  test "reports bare CR as invalid line ending" do
    scan = Lines.scan("line\rwith\rcr\n")

    assert [%{number: 1, text: "line\rwith\rcr"}] = scan.lines
    assert Enum.map(scan.errors, & &1.code) == ["invalid_line_ending", "invalid_line_ending"]
    assert Enum.map(scan.errors, & &1.line) == [1, 1]
  end

  test "reports non-empty final segment without LF" do
    scan = Lines.scan("only line")

    assert [%{number: 1, text: "only line"}] = scan.lines
    assert [%Diagnostic{code: "invalid_line_ending", line: 1}] = scan.errors
  end

  test "allows empty final segment after trailing LF" do
    scan = Lines.scan("line one\n")

    assert [%{number: 1, text: "line one"}] = scan.lines
    assert scan.errors == []
  end

  test "strips leading BOM and reports bom_present on line 1" do
    scan = Lines.scan("\uFEFFContact: mailto:a@example.com\n")

    assert [%{number: 1, text: "Contact: mailto:a@example.com"}] = scan.lines
    assert [%Diagnostic{code: "bom_present", line: 1}] = scan.errors
    assert scan.rejected == false
  end

  test "accepts exactly 1000 physical lines" do
    input = Enum.map_join(1..1000, "\n", &"line #{&1}") <> "\n"

    scan = Lines.scan(input)

    assert length(scan.lines) == 1000
    assert scan.errors == []
    assert scan.rejected == false
  end

  test "reports too_many_lines for 1001 physical lines without rejecting" do
    input = Enum.map_join(1..1001, "\n", &"line #{&1}") <> "\n"

    scan = Lines.scan(input)

    assert length(scan.lines) == 1001
    assert [%Diagnostic{code: "too_many_lines", line: nil}] = scan.errors
    assert scan.rejected == false
  end
end
