defmodule SecurityTxt.Field do
  @moduledoc false

  @type t :: %__MODULE__{
          name: String.t(),
          value: String.t(),
          line: pos_integer()
        }

  defstruct [:name, :value, :line]

  @spec to_map(t()) :: %{name: String.t(), value: String.t(), line: pos_integer()}
  def to_map(%__MODULE__{name: name, value: value, line: line}) do
    %{name: name, value: value, line: line}
  end

  @spec collect([t()]) :: %{
          contact: [String.t()],
          expires: String.t() | nil,
          acknowledgments: [String.t()],
          canonical: [String.t()],
          csaf: [String.t()],
          encryption: [String.t()],
          hiring: [String.t()],
          policy: [String.t()],
          preferred_languages: [String.t()]
        }
  def collect(fields) do
    Enum.reduce(fields, empty_collection(), &collect_field/2)
  end

  defp empty_collection do
    %{
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

  defp collect_field(%__MODULE__{name: name, value: value}, acc) do
    case String.downcase(name) do
      "contact" -> %{acc | contact: acc.contact ++ [value]}
      "expires" -> if acc.expires, do: acc, else: %{acc | expires: value}
      "acknowledgments" -> %{acc | acknowledgments: acc.acknowledgments ++ [value]}
      "canonical" -> %{acc | canonical: acc.canonical ++ [value]}
      "csaf" -> %{acc | csaf: acc.csaf ++ [value]}
      "encryption" -> %{acc | encryption: acc.encryption ++ [value]}
      "hiring" -> %{acc | hiring: acc.hiring ++ [value]}
      "policy" -> %{acc | policy: acc.policy ++ [value]}
      "preferred-languages" -> %{acc | preferred_languages: acc.preferred_languages ++ [value]}
      _ -> acc
    end
  end
end
