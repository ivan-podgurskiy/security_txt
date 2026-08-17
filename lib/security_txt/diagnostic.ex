defmodule SecurityTxt.Diagnostic do
  @moduledoc false

  @messages %{
    no_contact: "At least one Contact field is required.",
    no_expires: "At least one Expires field is required.",
    multi_expires: "Only one Expires field is allowed.",
    multi_lang: "Only one Preferred-Languages field is allowed.",
    invalid_expires: "The Expires field must contain a valid RFC 3339 timestamp.",
    expired: "The Expires field is in the past.",
    invalid_uri: "The field value must be a valid absolute URI.",
    invalid_contact_scheme: "The Contact field must use an allowed URI scheme.",
    invalid_https_field: "This field requires an HTTPS URI.",
    invalid_lang: "The Preferred-Languages field contains an invalid language tag.",
    invalid_line: "The line is not a valid security.txt field.",
    bom_present: "A UTF-8 byte order mark is not allowed.",
    invalid_line_ending: "Only CRLF or LF line endings are allowed.",
    file_too_large: "The file exceeds the maximum allowed size.",
    too_many_lines: "The file exceeds the maximum allowed number of lines.",
    field_too_long: "The field value exceeds the maximum allowed length.",
    long_expiry: "The Expires value is more than one year in the future.",
    no_encryption: "An Encryption field is recommended.",
    not_signed: "The security.txt file is not signed.",
    no_canonical: "A Canonical field is recommended.",
    multi_csaf: "Only one CSAF field is allowed.",
    unknown_field: "The field name is not recognized."
  }

  @type code_atom ::
          :no_contact | :no_expires | :multi_expires | :multi_lang |
          :invalid_expires | :expired | :invalid_uri |
          :invalid_contact_scheme | :invalid_https_field | :invalid_lang |
          :invalid_line | :bom_present | :invalid_line_ending |
          :file_too_large | :too_many_lines | :field_too_long |
          :long_expiry | :no_encryption | :not_signed |
          :no_canonical | :multi_csaf | :unknown_field

  @type t :: %__MODULE__{
          code: String.t(),
          message: String.t(),
          line: non_neg_integer() | nil
        }

  defstruct [:code, :message, :line]

  @spec new(code_atom(), non_neg_integer() | nil) :: t()
  def new(code_atom, line) when is_atom(code_atom) do
    code = Atom.to_string(code_atom)
    message = Map.fetch!(@messages, code_atom)

    %__MODULE__{code: code, message: message, line: line}
  end

  @spec to_map(t()) :: %{code: String.t(), message: String.t(), line: non_neg_integer() | nil}
  def to_map(%__MODULE__{code: code, message: message, line: line}) do
    %{code: code, message: message, line: line}
  end
end
