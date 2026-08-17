defmodule SecurityTxt.OpenPgp do
  @moduledoc false

  alias SecurityTxt.Lines

  @begin_signed "-----BEGIN PGP SIGNED MESSAGE-----"
  @begin_signature "-----BEGIN PGP SIGNATURE-----"
  @end_signature "-----END PGP SIGNATURE-----"
  @hash_prefix "Hash: "

  @type physical_line :: Lines.physical_line()
  @type extract_result :: %{signed: boolean(), lines: [physical_line()]}

  @spec extract([physical_line()]) :: extract_result()
  def extract(lines) do
    case extract_signed(lines) do
      {:ok, cleartext} -> %{signed: true, lines: cleartext}
      :error -> %{signed: false, lines: lines}
    end
  end

  defp extract_signed([%{text: @begin_signed} | rest]) do
    with {:ok, rest} <- consume_hash_headers(rest),
         {:ok, rest} <- require_blank_line(rest),
         {:ok, cleartext, rest} <- collect_cleartext(rest),
         {:ok, _} <- require_end_signature(rest) do
      {:ok, Enum.map(cleartext, &dash_unescape/1)}
    else
      :error -> :error
    end
  end

  defp extract_signed(_), do: :error

  defp consume_hash_headers([%{text: @hash_prefix <> _} | rest]) do
    consume_more_hash_headers(rest)
  end

  defp consume_hash_headers(_), do: :error

  defp consume_more_hash_headers([%{text: @hash_prefix <> _} | rest]) do
    consume_more_hash_headers(rest)
  end

  defp consume_more_hash_headers(rest), do: {:ok, rest}

  defp require_blank_line([%{text: ""} | rest]), do: {:ok, rest}
  defp require_blank_line(_), do: :error

  defp collect_cleartext(lines, acc \\ [])

  defp collect_cleartext([%{text: @begin_signature} | rest], acc) do
    {:ok, Enum.reverse(acc), rest}
  end

  defp collect_cleartext([line | rest], acc) do
    collect_cleartext(rest, [line | acc])
  end

  defp collect_cleartext([], _acc), do: :error

  defp require_end_signature(lines) do
    if Enum.any?(lines, &match?(%{text: @end_signature}, &1)) do
      {:ok, lines}
    else
      :error
    end
  end

  defp dash_unescape(%{number: number, text: "- " <> rest}) do
    %{number: number, text: rest}
  end

  defp dash_unescape(line), do: line
end
