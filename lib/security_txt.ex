defmodule SecurityTxt do
  @moduledoc """
  Provides the public API for parsing, validating, and serializing RFC 9116
  `security.txt` files.

  The package has no runtime dependencies. Its public parsing and serialization
  functions are introduced as the implementation is completed.
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

  @spec serialize(keyword()) :: String.t()
  def serialize(options) when is_list(options) do
    Serializer.serialize(options)
  end

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
