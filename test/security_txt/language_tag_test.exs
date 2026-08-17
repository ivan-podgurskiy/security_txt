defmodule SecurityTxt.LanguageTagTest do
  use ExUnit.Case, async: true

  alias SecurityTxt.LanguageTag

  @valid_required_cases [
    "en",
    "en-US",
    "zh-Hant",
    "de-CH-1901",
    "sl-rozaj-biske",
    "x-private",
    "en-x-acme",
    "i-klingon",
    "sgn-BE-FR"
  ]

  for value <- @valid_required_cases do
    test "accepts the required valid case #{value}" do
      assert LanguageTag.valid?(unquote(value))
    end
  end

  @valid_production_cases [
    "aa",
    "aaa",
    "abcd",
    "abcde",
    "abcdefgh",
    "zh-cmn",
    "zh-cmn-yue",
    "zh-cmn-yue-gan",
    "zh-cmn-Hans-CN",
    "sr-Latn-RS",
    "es-419",
    "sl-rozaj-biske-1994",
    "en-a-abc",
    "en-0-abc-b-def",
    "en-a-12-b-abcdef12-x-private-tail",
    "x-a",
    "x-private-12345678",
    "en-x-a"
  ]

  for value <- @valid_production_cases do
    test "accepts RFC 5646 production #{value}" do
      assert LanguageTag.valid?(unquote(value))
    end
  end

  @grandfathered_cases [
    "en-GB-oed",
    "i-ami",
    "i-bnn",
    "i-default",
    "i-enochian",
    "i-hak",
    "i-klingon",
    "i-lux",
    "i-mingo",
    "i-navajo",
    "i-pwn",
    "i-tao",
    "i-tay",
    "i-tsu",
    "sgn-BE-FR",
    "sgn-BE-NL",
    "sgn-CH-DE",
    "art-lojban",
    "cel-gaulish",
    "no-bok",
    "no-nyn",
    "zh-guoyu",
    "zh-hakka",
    "zh-min",
    "zh-min-nan",
    "zh-xiang"
  ]

  for value <- @grandfathered_cases do
    test "accepts grandfathered tag #{value} case-insensitively" do
      assert LanguageTag.valid?(unquote(value))
      assert LanguageTag.valid?(String.upcase(unquote(value)))
    end
  end

  @invalid_cases [
    "",
    "en_US",
    "en-",
    "-en",
    "en--US",
    "a",
    "abcdefghi",
    "zh-cmn-yue-gan-wuu",
    "en-a",
    "en-a-z",
    "en-a-123456789",
    "en-a-abc-A-def",
    "en-0-abc-0-def",
    "x",
    "x-",
    "x-123456789",
    "en-x",
    "en-x-",
    "en-US-abcd",
    "de-1901-1901",
    "en-a-abc-!",
    "en a"
  ]

  for value <- @invalid_cases do
    test "rejects malformed or forbidden tag #{inspect(value)}" do
      refute LanguageTag.valid?(unquote(value))
    end
  end

  describe "parse_list/1" do
    test "returns a trimmed list while preserving case and order" do
      assert LanguageTag.parse_list("en, pt-BR, zh-Hant") == {:ok, ["en", "pt-BR", "zh-Hant"]}
      assert LanguageTag.parse_list("en, ,fr") == :error
    end

    for value <- ["en, ,fr", "", "en,fr,", ",en", "en,en_US"] do
      test "rejects an invalid list #{inspect(value)}" do
        assert LanguageTag.parse_list(unquote(value)) == :error
      end
    end

    test "preserves accepted casing, order, and duplicates" do
      assert LanguageTag.parse_list(" EN-us, i-KLINGON, EN-us ") ==
               {:ok, ["EN-us", "i-KLINGON", "EN-us"]}
    end
  end
end
