defmodule SecurityTxt.LanguageTag do
  @moduledoc false

  @alpha ~r/^[A-Za-z]+$/
  @script ~r/^[A-Za-z]{4}$/
  @region ~r/^(?:[A-Za-z]{2}|[0-9]{3})$/
  @variant ~r/^(?:[A-Za-z0-9]{5,8}|[0-9][A-Za-z0-9]{3})$/
  @singleton ~r/^[0-9A-WY-Za-wy-z]$/

  @private_use ~r/^x(?:-[A-Za-z0-9]{1,8})+$/i
  @langtag ~r/^(?:[A-Za-z]{2,3}(?:-[A-Za-z]{3}){0,3}|[A-Za-z]{4}|[A-Za-z]{5,8})(?:-[A-Za-z]{4})?(?:-(?:[A-Za-z]{2}|[0-9]{3}))?(?:-(?:[A-Za-z0-9]{5,8}|[0-9][A-Za-z0-9]{3}))*(?:-[0-9A-WY-Za-wy-z](?:-[A-Za-z0-9]{2,8})+)*(?:-x(?:-[A-Za-z0-9]{1,8})+)?$/i

  @grandfathered MapSet.new([
                   "en-gb-oed",
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
                   "sgn-be-fr",
                   "sgn-be-nl",
                   "sgn-ch-de",
                   "art-lojban",
                   "cel-gaulish",
                   "no-bok",
                   "no-nyn",
                   "zh-guoyu",
                   "zh-hakka",
                   "zh-min",
                   "zh-min-nan",
                   "zh-xiang"
                 ])

  @spec valid?(String.t()) :: boolean()
  def valid?(value) do
    normalized = String.downcase(value, :ascii)

    cond do
      MapSet.member?(@grandfathered, normalized) -> true
      Regex.match?(@private_use, value) -> true
      Regex.match?(@langtag, value) -> unique_variants_and_extensions?(value)
      true -> false
    end
  end

  @spec parse_list(String.t()) :: {:ok, [String.t()]} | :error
  def parse_list(value) do
    tags =
      value
      |> String.split(",")
      |> Enum.map(&String.trim/1)

    if Enum.all?(tags, &valid?/1) and Enum.all?(tags, &(&1 != "")) do
      {:ok, tags}
    else
      :error
    end
  end

  defp unique_variants_and_extensions?(value) do
    subtags = String.split(value, "-")
    index = language_subtag_end(subtags)

    index =
      if Regex.match?(@script, Enum.at(subtags, index) || "") do
        index + 1
      else
        index
      end

    index =
      if Regex.match?(@region, Enum.at(subtags, index) || "") do
        index + 1
      else
        index
      end

    index =
      case skip_variants(subtags, index, MapSet.new()) do
        :duplicate -> :duplicate
        next_index -> next_index
      end

    case index do
      :duplicate ->
        false

      index ->
        case skip_extensions(subtags, index, MapSet.new()) do
          :duplicate -> false
          _index -> true
        end
    end
  end

  @spec skip_variants([String.t()], non_neg_integer(), MapSet.t(String.t())) ::
          non_neg_integer() | :duplicate
  defp skip_variants(subtags, index, variants) do
    case Enum.at(subtags, index) do
      subtag when is_binary(subtag) ->
        if Regex.match?(@variant, subtag) do
          variant = String.downcase(subtag, :ascii)

          if MapSet.member?(variants, variant) do
            :duplicate
          else
            skip_variants(subtags, index + 1, MapSet.put(variants, variant))
          end
        else
          index
        end

      _ ->
        index
    end
  end

  @spec skip_extensions([String.t()], non_neg_integer(), MapSet.t(String.t())) ::
          non_neg_integer() | :duplicate
  defp skip_extensions(subtags, index, singletons) do
    case Enum.at(subtags, index) do
      subtag when is_binary(subtag) ->
        if Regex.match?(@singleton, subtag) do
          singleton = String.downcase(subtag, :ascii)

          if MapSet.member?(singletons, singleton) do
            :duplicate
          else
            index = index + 1
            index = skip_extension_subtags(subtags, index)
            skip_extensions(subtags, index, MapSet.put(singletons, singleton))
          end
        else
          index
        end

      _ ->
        index
    end
  end

  defp skip_extension_subtags(subtags, index) do
    case Enum.at(subtags, index) do
      subtag when is_binary(subtag) ->
        if byte_size(subtag) != 1 and String.downcase(subtag, :ascii) != "x" do
          skip_extension_subtags(subtags, index + 1)
        else
          index
        end

      _ ->
        index
    end
  end

  defp language_subtag_end(subtags) do
    primary = Enum.at(subtags, 0)

    if is_nil(primary) or String.length(primary) < 2 or String.length(primary) > 3 do
      1
    else
      language_subtag_end(subtags, 1, 0)
    end
  end

  defp language_subtag_end(subtags, index, extlang_count) when extlang_count < 3 do
    case Enum.at(subtags, index) do
      subtag when is_binary(subtag) ->
        if String.length(subtag) == 3 and Regex.match?(@alpha, subtag) do
          language_subtag_end(subtags, index + 1, extlang_count + 1)
        else
          index
        end

      _ ->
        index
    end
  end

  defp language_subtag_end(_subtags, index, _extlang_count), do: index
end
