defmodule SecurityTxt.Lines do
  @moduledoc false

  alias SecurityTxt.Diagnostic

  @max_bytes 32_768
  @max_lines 1_000
  @bom "\uFEFF"

  @type physical_line :: %{number: pos_integer(), text: String.t()}

  @type scan_result :: %{
          lines: [physical_line()],
          errors: [Diagnostic.t()],
          rejected: boolean()
        }

  @spec scan(String.t()) :: scan_result()
  def scan(input) when is_binary(input) do
    if byte_size(input) > @max_bytes do
      %{
        lines: [],
        errors: [Diagnostic.new(:file_too_large, nil)],
        rejected: true
      }
    else
      scan_within_limit(input)
    end
  end

  defp scan_within_limit(""), do: %{lines: [], errors: [], rejected: false}

  defp scan_within_limit(input) do
    {input, bom_errors} = strip_bom(input)

    {lines, ending_errors} = split_lines(input)

    line_count_errors =
      if length(lines) > @max_lines do
        [Diagnostic.new(:too_many_lines, nil)]
      else
        []
      end

    %{
      lines: lines,
      errors: bom_errors ++ ending_errors ++ line_count_errors,
      rejected: false
    }
  end

  defp strip_bom(@bom <> rest) do
    {rest, [Diagnostic.new(:bom_present, 1)]}
  end

  defp strip_bom(input), do: {input, []}

  defp split_lines(input) do
    segments = String.split(input, "\n", parts: :infinity)
    has_trailing_lf = String.ends_with?(input, "\n")

    segments =
      if has_trailing_lf do
        Enum.drop(segments, -1)
      else
        segments
      end

    split_segments(segments, 1, has_trailing_lf, [], [])
    |> then(fn {lines, errors} -> {Enum.reverse(lines), Enum.reverse(errors)} end)
  end

  defp split_segments([], _number, _has_trailing_lf, lines, errors), do: {lines, errors}

  defp split_segments([segment], number, has_trailing_lf, lines, errors) do
    {text, cr_errors} = strip_crlf_ending(segment, number)
    line = %{number: number, text: text}
    ending_errors = cr_errors ++ maybe_missing_final_lf(text, number, has_trailing_lf)
    {[line | lines], ending_errors ++ errors}
  end

  defp split_segments([segment | rest], number, has_trailing_lf, lines, errors) do
    {text, cr_errors} = strip_crlf_ending(segment, number)
    line = %{number: number, text: text}
    split_segments(rest, number + 1, has_trailing_lf, [line | lines], cr_errors ++ errors)
  end

  defp strip_crlf_ending(segment, line_number) do
    text =
      case String.ends_with?(segment, "\r") do
        true -> String.slice(segment, 0, String.length(segment) - 1)
        false -> segment
      end

    cr_errors =
      text
      |> :binary.matches("\r")
      |> Enum.map(fn _ -> Diagnostic.new(:invalid_line_ending, line_number) end)

    {text, cr_errors}
  end

  defp maybe_missing_final_lf("", _number, _has_trailing_lf), do: []

  defp maybe_missing_final_lf(_text, _number, true), do: []

  defp maybe_missing_final_lf(_text, number, false) do
    [Diagnostic.new(:invalid_line_ending, number)]
  end
end
