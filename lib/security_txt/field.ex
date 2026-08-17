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
end
