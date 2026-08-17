defmodule SecurityTxt do
  @moduledoc """
  Provides the public API for parsing, validating, and serializing RFC 9116
  `security.txt` files.

  The package has no runtime dependencies. Its public parsing and serialization
  functions are introduced as the implementation is completed.
  """

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
end
