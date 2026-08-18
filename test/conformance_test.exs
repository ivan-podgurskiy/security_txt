defmodule ConformanceTest do
  use ExUnit.Case, async: false

  @fixture_path Path.join([__DIR__, "fixtures", "conformance.json"])

  setup_all do
    unless File.exists?(@fixture_path) do
      raise File.Error,
        reason: :enoent,
        action: "read file",
        path: @fixture_path
    end

    Conformance.configure!(@fixture_path)
    :ok
  end

  describe "shared conformance fixture" do
    test "parse cases" do
      Enum.each(Conformance.parse_cases(), fn fixture_case ->
        actual = Conformance.run_parse_case(fixture_case)
        expected = Conformance.expected_parse(fixture_case)

        assert Conformance.matches_object?(actual, expected),
               "expected subset match for #{fixture_case["name"]}"
      end)
    end

    test "serialize cases" do
      Enum.each(Conformance.serialize_cases(), fn fixture_case ->
        result = Conformance.run_serialize_case(fixture_case)
        expected = Conformance.expected_serialize(fixture_case)

        case expected do
          :throws ->
            assert {:error, :argument_error} = result,
                   "expected ArgumentError for #{fixture_case["name"]}"

          expected_output ->
            assert {:ok, output} = result, "serialize failed for #{fixture_case["name"]}"

            assert output == expected_output,
                   "output mismatch for #{fixture_case["name"]}"
        end
      end)
    end
  end
end
