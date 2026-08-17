defmodule SecurityTxt.ExpiresTest do
  use ExUnit.Case, async: true

  alias SecurityTxt.Expires

  describe "parse/1" do
    @valid_cases [
      {"2028-02-29T12:34:56Z", ~U[2028-02-29 12:34:56Z]},
      {"2028-02-29t12:34:56z", ~U[2028-02-29 12:34:56Z]},
      {"2028-02-29t14:34:56+02:00", ~U[2028-02-29 12:34:56Z]},
      {"2028-02-29T10:04:56-02:30", ~U[2028-02-29 12:34:56Z]},
      {"2028-02-29T12:34:56.123456789Z", ~U[2028-02-29 12:34:56.123456Z]},
      {"0000-01-01T00:00:00Z", ~U[0000-01-01 00:00:00Z]},
      {"1990-12-31T23:59:60Z", ~U[1991-01-01 00:00:00Z]},
      {"1991-01-01T00:59:60+01:00", ~U[1991-01-01 00:00:00Z]}
    ]

    for {value, expected} <- @valid_cases do
      test "parses valid RFC 3339 value #{value}" do
        assert {:ok, unquote(Macro.escape(expected))} = Expires.parse(unquote(value))
      end
    end

    @invalid_cases [
      "2027-02-29T12:00:00Z",
      "2028-02-30T12:00:00Z",
      "2028-00-01T12:00:00Z",
      "2028-13-01T12:00:00Z",
      "2028-01-01T24:00:00Z",
      "2028-01-01T12:60:00Z",
      "2028-01-01T12:00:00+24:00",
      "2028-01-01T12:00:00+00:60",
      "2028-01-01T12:00:00Z trailing",
      "2028-01-01 12:00:00Z",
      "2028-01-01T12:00:00",
      "2028-01-01T12:00:00.Z"
    ]

    for value <- @invalid_cases do
      test "rejects malformed or impossible value #{value}" do
        assert :error = Expires.parse(unquote(value))
      end
    end

    @invalid_leap_second_cases [
      "2028-01-01T12:00:60Z",
      "2028-06-30T23:58:60Z",
      "2028-07-01T01:59:60+01:00"
    ]

    for value <- @invalid_leap_second_cases do
      test "rejects second 60 outside a possible positive leap second #{value}" do
        assert :error = Expires.parse(unquote(value))
      end
    end
  end

  describe "classify/2" do
    test "classifies invalid values" do
      now = ~U[2028-01-15 12:00:00Z]
      assert Expires.classify("2028-02-30T12:00:00Z", now) == :invalid
    end

    test "treats the exact current instant as current" do
      now = ~U[2028-01-15 12:00:00Z]
      assert Expires.classify("2028-01-15T12:00:00Z", now) == :current
    end

    test "treats an instant one microsecond in the past as expired" do
      now = ~U[2028-01-15 12:00:00Z]
      assert Expires.classify("2028-01-15T11:59:59.999999Z", now) == :expired
    end

    test "uses a calendar year for the recommendation boundary" do
      now = ~U[2028-02-29 12:00:00Z]
      assert Expires.classify("2029-02-28T12:00:00Z", now) == :current
      assert Expires.classify("2029-02-28T12:00:00.000001Z", now) == :long
    end

    test "keeps the same UTC date and time for a normal one-year boundary" do
      now = ~U[2028-01-15 12:00:00Z]
      assert Expires.classify("2029-01-15T12:00:00Z", now) == :current
      assert Expires.classify("2029-01-15T12:00:00.000001Z", now) == :long
    end

    test "compares offset-equivalent timestamps as the same instant" do
      now = ~U[2028-01-15 12:00:00Z]
      assert Expires.classify("2028-01-15T14:00:00+02:00", now) == :current
      assert Expires.classify("2028-01-15T13:59:59.999999+02:00", now) == :expired
    end
  end
end
