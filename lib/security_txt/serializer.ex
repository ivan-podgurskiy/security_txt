defmodule SecurityTxt.Serializer do
  @moduledoc false

  alias SecurityTxt.Expires
  alias SecurityTxt.LanguageTag
  alias SecurityTxt.Uri

  @max_file_bytes 32_768
  @max_physical_lines 1_000
  @max_field_code_points 2_048

  @allowed_keys ~w(
    comments
    contact
    expires
    acknowledgments
    canonical
    csaf
    encryption
    hiring
    policy
    preferred_languages
  )a

  @uri_fields [
    {:contact, "Contact", true},
    {:acknowledgments, "Acknowledgments", false},
    {:canonical, "Canonical", false},
    {:csaf, "CSAF", false},
    {:encryption, "Encryption", false},
    {:hiring, "Hiring", false},
    {:policy, "Policy", false}
  ]

  @spec serialize(keyword()) :: String.t()
  def serialize(options) when is_list(options) do
    reject_unknown_keys!(options)

    comments = normalize_comments(Keyword.get(options, :comments))
    values_by_option = normalize_uri_fields(options)
    expiry = normalize_expiry(fetch_required!(options, :expires, "Expires"))
    languages = normalize_preferred_languages(Keyword.get(options, :preferred_languages))

    lines = build_lines(comments, values_by_option, expiry, languages)
    output = Enum.join(lines, "\n") <> "\n"

    assert_resource_limits!(lines, output)

    output
  end

  def serialize(_), do: invalid_options("options must be a keyword list")

  defp reject_unknown_keys!(options) do
    unknown = Enum.uniq(Keyword.keys(options)) -- @allowed_keys

    if unknown != [] do
      invalid_options("unknown option keys")
    end
  end

  defp fetch_required!(options, key, name) do
    case Keyword.get(options, key) do
      nil -> invalid_options("#{name} is required")
      value -> value
    end
  end

  defp normalize_comments(nil), do: nil

  defp normalize_comments(comments) when is_list(comments) do
    if comments == [] do
      invalid_options("comments must be a non-empty array")
    else
      Enum.each(comments, fn
        comment when is_binary(comment) -> assert_single_line!(comment, "comments")
        _ -> invalid_options("comments must contain only strings")
      end)

      comments
    end
  end

  defp normalize_comments(_), do: invalid_options("comments must be a non-empty array")

  defp normalize_uri_fields(options) do
    Enum.reduce(@uri_fields, %{}, fn {option, name, required?}, acc ->
      case normalize_strings(Keyword.get(options, option), name, required?) do
        nil ->
          acc

        values ->
          validate_uri_values!(name, values)
          Map.put(acc, option, values)
      end
    end)
  end

  defp normalize_strings(nil, name, true), do: invalid_options("#{name} is required")
  defp normalize_strings(nil, _name, false), do: nil

  defp normalize_strings(value, name, _required?) when is_binary(value) do
    assert_single_line!(value, name)
    [value]
  end

  defp normalize_strings(values, name, _required?) when is_list(values) do
    if values == [] do
      invalid_options("#{name} must be a string or non-empty array")
    else
      Enum.each(values, fn
        item when is_binary(item) -> assert_single_line!(item, name)
        _ -> invalid_options("#{name} values must be strings")
      end)

      values
    end
  end

  defp normalize_strings(_value, name, _required?) do
    invalid_options("#{name} must be a string or non-empty array")
  end

  defp normalize_expiry(%DateTime{} = value) do
    value
    |> DateTime.shift_zone!("Etc/UTC")
    |> DateTime.to_iso8601()
    |> strip_zero_fraction()
    |> validate_expiry_value!()
  end

  defp normalize_expiry(value) when is_binary(value) do
    value
    |> tap(&assert_single_line!(&1, "expires"))
    |> validate_expiry_value!()
  end

  defp normalize_expiry(_), do: invalid_options("expires must be a DateTime or string")

  defp validate_expiry_value!(expiry) do
    case Expires.classify(expiry, DateTime.utc_now()) do
      classification when classification in [:invalid, :expired] ->
        invalid_options("expires must be a current RFC 3339 timestamp")

      _ ->
        expiry
    end
  end

  defp normalize_preferred_languages(nil), do: nil

  defp normalize_preferred_languages(value) do
    languages = normalize_strings(value, "Preferred-Languages", false)

    if Enum.any?(languages, &(not LanguageTag.valid?(&1))) do
      invalid_options("Preferred-Languages contains an invalid tag")
    else
      languages
    end
  end

  defp build_lines(comments, values_by_option, expiry, languages) do
    comment_lines =
      case comments do
        nil -> []
        comments -> Enum.map(comments, &"# #{&1}")
      end

    contact_lines =
      Enum.map(Map.get(values_by_option, :contact, []), &"Contact: #{&1}")

    other_uri_lines =
      @uri_fields
      |> Enum.drop(1)
      |> Enum.flat_map(fn {option, name, _} ->
        Enum.map(Map.get(values_by_option, option, []), &"#{name}: #{&1}")
      end)

    language_lines =
      case languages do
        nil -> []
        languages -> ["Preferred-Languages: #{Enum.join(languages, ", ")}"]
      end

    comment_lines ++ contact_lines ++ ["Expires: #{expiry}"] ++ other_uri_lines ++ language_lines
  end

  defp validate_uri_values!(name, values) do
    Enum.each(values, fn value ->
      if Uri.validate(name, value, 1) do
        invalid_options("#{name} contains an invalid URI")
      end
    end)
  end

  defp assert_resource_limits!(lines, output) do
    if length(lines) > @max_physical_lines do
      invalid_options("serialized content exceeds the line limit")
    end

    Enum.each(lines, fn line ->
      if not String.starts_with?(line, "#") and codepoint_count(line) > @max_field_code_points do
        invalid_options("a serialized field exceeds the length limit")
      end
    end)

    if byte_size(output) > @max_file_bytes do
      invalid_options("serialized content exceeds the file size limit")
    end
  end

  defp codepoint_count(line) do
    line |> String.codepoints() |> length()
  end

  defp assert_single_line!(value, name) do
    if String.contains?(value, ["\r", "\n"]) do
      invalid_options("#{name} must not contain CR or LF")
    end
  end

  defp strip_zero_fraction(iso) do
    iso
    |> String.replace_suffix(".000000Z", "Z")
    |> String.replace_suffix(".000Z", "Z")
  end

  defp invalid_options(reason) do
    raise ArgumentError, "Invalid serialization options: #{reason}"
  end
end
