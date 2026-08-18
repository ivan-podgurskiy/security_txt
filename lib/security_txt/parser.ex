defmodule SecurityTxt.Parser do
  @moduledoc false

  alias SecurityTxt.Diagnostic
  alias SecurityTxt.Field

  @field_name ~r/^[\x21-\x39\x3b-\x7e]+:(.*)$/

  @registered_names MapSet.new([
                      "contact",
                      "expires",
                      "acknowledgments",
                      "canonical",
                      "csaf",
                      "encryption",
                      "hiring",
                      "policy",
                      "preferred-languages"
                    ])

  @spec parse_lines([%{number: pos_integer(), text: String.t()}]) ::
          {[Field.t()], [Diagnostic.t()]}
  def parse_lines(lines) do
    Enum.reduce(lines, {[], []}, &parse_line/2)
    |> then(fn {fields, errors} -> {Enum.reverse(fields), Enum.reverse(errors)} end)
  end

  defp parse_line(%{number: line_number, text: text}, {fields, errors}) do
    cond do
      blank_line?(text) ->
        {fields, errors}

      comment_line?(text) ->
        {fields, errors}

      true ->
        case parse_field_line(text, line_number) do
          {:ok, field} ->
            {[field | fields], errors}

          {:error, diagnostic} ->
            {fields, [diagnostic | errors]}
        end
    end
  end

  defp blank_line?(text), do: text =~ ~r/^[ \t]*$/

  defp comment_line?(text), do: String.starts_with?(text, "#")

  defp parse_field_line(text, line_number) do
    case Regex.run(@field_name, text) do
      [_, value_part] ->
        value = String.trim(value_part)

        if value == "" do
          {:error, Diagnostic.new(:invalid_line, line_number)}
        else
          name = text |> String.split(":", parts: 2) |> hd()
          maybe_validate_length(text, line_number, name, value)
        end

      nil ->
        {:error, Diagnostic.new(:invalid_line, line_number)}
    end
  end

  defp maybe_validate_length(text, line_number, name, value) do
    field = %Field{name: name, value: value, line: line_number}

    if MapSet.member?(@registered_names, String.downcase(name)) and
         String.length(text) > 2048 do
      {:error, Diagnostic.new(:field_too_long, line_number)}
    else
      {:ok, field}
    end
  end
end
