defmodule SecurityTxt do
  @moduledoc """
  Parse, validate, and serialize RFC 9116 `security.txt` files in Elixir.

  The package has no runtime dependencies. Parsing returns structured
  diagnostics, convenience accessors for registered fields, and OpenPGP
  cleartext detection. Serialization builds canonical unsigned documents from
  validated keyword options.

  ## Quick start

      expires =
        DateTime.utc_now()
        |> DateTime.add(2 * 365 * 24 * 60 * 60, :second)
        |> DateTime.to_iso8601()

      result =
        SecurityTxt.parse(\"\"\"
        Contact: https://example.com/report
        Expires: \#{expires}
        Policy: https://example.com/security-policy
        Preferred-Languages: en, tr
        \"\"\")

      result.valid
      #=> true

      result.contact
      #=> ["https://example.com/report"]

      Enum.map(result.recommendations, & &1.code)
      #=> ["long_expiry", "not_signed"]

  ## Serialize

      expires =
        DateTime.utc_now()
        |> DateTime.add(2 * 365 * 24 * 60 * 60, :second)
        |> DateTime.to_iso8601()

      SecurityTxt.serialize(
        comments: ["Security contact for example.com"],
        contact: ["mailto:security@example.com", "https://example.com/report"],
        expires: expires,
        canonical: "https://example.com/.well-known/security.txt",
        csaf: "https://example.com/.well-known/csaf/provider-metadata.json",
        encryption: "openpgp4fpr:0123456789ABCDEF",
        policy: "https://example.com/security-policy",
        preferred_languages: ["en", "tr"]
      )

  See the [README](README.md) for the full API, diagnostic codes, and scope.
  """

  alias SecurityTxt.Diagnostic
  alias SecurityTxt.Field
  alias SecurityTxt.Lines
  alias SecurityTxt.OpenPgp
  alias SecurityTxt.Parser
  alias SecurityTxt.Serializer
  alias SecurityTxt.Validator

  @typedoc "A parsed RFC 9116 field."
  @type field :: %{
          required(:name) => String.t(),
          required(:value) => String.t(),
          required(:line) => pos_integer()
        }

  @typedoc "A diagnostic produced while processing a security.txt file."
  @type diagnostic :: %{
          required(:code) => String.t(),
          required(:message) => String.t(),
          required(:line) => pos_integer() | nil
        }

  @typedoc "The public result returned by the parser."
  @type result :: %{
          required(:valid) => boolean(),
          required(:errors) => [diagnostic()],
          required(:recommendations) => [diagnostic()],
          required(:notifications) => [diagnostic()],
          required(:fields) => [field()],
          required(:signed) => boolean(),
          required(:contact) => [String.t()],
          required(:expires) => String.t() | nil,
          required(:acknowledgments) => [String.t()],
          required(:canonical) => [String.t()],
          required(:csaf) => [String.t()],
          required(:encryption) => [String.t()],
          required(:hiring) => [String.t()],
          required(:policy) => [String.t()],
          required(:preferred_languages) => [String.t()]
        }

  @doc """
  Builds a validated unsigned `security.txt` document.

  `:contact` and `:expires` are required. URI and language fields accept a
  string or non-empty string list; `:comments` accepts a non-empty string list.
  An `:expires` value may be a current RFC 3339 string or a `DateTime`.

  The output uses LF line endings, canonical field order, and one trailing
  newline. Invalid options raise `ArgumentError`.

  ## Examples

      expires =
        DateTime.utc_now()
        |> DateTime.add(2 * 365 * 24 * 60 * 60, :second)
        |> DateTime.to_iso8601()

      SecurityTxt.serialize(
        comments: ["Security contact for example.com"],
        contact: ["mailto:security@example.com", "https://example.com/report"],
        expires: expires,
        canonical: "https://example.com/.well-known/security.txt",
        csaf: "https://example.com/.well-known/csaf/provider-metadata.json",
        encryption: "openpgp4fpr:0123456789ABCDEF",
        policy: "https://example.com/security-policy",
        preferred_languages: ["en", "tr"]
      )
  """
  @spec serialize(keyword()) :: String.t()
  def serialize(options) do
    Serializer.serialize(options)
  end

  @doc """
  Parses and validates a complete `security.txt` string.

  Parsing malformed input does not raise. Input over 32,768 UTF-8 bytes is
  rejected before fields are parsed. The result includes source-order fields,
  convenience accessors, and diagnostics separated by severity.

  ## Examples

      expires =
        DateTime.utc_now()
        |> DateTime.add(2 * 365 * 24 * 60 * 60, :second)
        |> DateTime.to_iso8601()

      SecurityTxt.parse(\"\"\"
      Contact: https://example.com/report
      Expires: \#{expires}
      Policy: https://example.com/security-policy
      Preferred-Languages: en, tr
      \"\"\")

  """
  @spec parse(String.t()) :: result()
  def parse(content) when is_binary(content) do
    scanned = Lines.scan(content)

    if scanned.rejected do
      empty_result(scanned.errors)
    else
      cleartext = OpenPgp.extract(scanned.lines)
      {fields, parse_errors} = Parser.parse_lines(cleartext.lines)

      physical_errors =
        sort_physical_errors(scanned.errors ++ parse_errors)

      collected = Field.collect(fields)
      validation = Validator.validate(fields, cleartext.signed, DateTime.utc_now())
      errors = physical_errors ++ validation.errors

      %{
        valid: errors == [],
        errors: Enum.map(errors, &Diagnostic.to_map/1),
        recommendations: Enum.map(validation.recommendations, &Diagnostic.to_map/1),
        notifications: Enum.map(validation.notifications, &Diagnostic.to_map/1),
        fields: Enum.map(fields, &Field.to_map/1),
        signed: cleartext.signed,
        contact: collected.contact,
        expires: collected.expires,
        acknowledgments: collected.acknowledgments,
        canonical: collected.canonical,
        csaf: collected.csaf,
        encryption: collected.encryption,
        hiring: collected.hiring,
        policy: collected.policy,
        preferred_languages: validation.preferred_languages
      }
    end
  end

  defp empty_result(errors) do
    %{
      valid: errors == [],
      errors: Enum.map(errors, &Diagnostic.to_map/1),
      recommendations: [],
      notifications: [],
      fields: [],
      signed: false,
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

  defp sort_physical_errors(errors) do
    Enum.sort_by(errors, fn %{line: line} ->
      if line == nil, do: {1, 0}, else: {0, line}
    end)
  end
end
