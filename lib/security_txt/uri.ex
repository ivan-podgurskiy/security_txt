defmodule SecurityTxt.Uri do
  @moduledoc false

  alias SecurityTxt.Diagnostic

  @https_fields ~w(acknowledgments canonical csaf hiring policy)
  @uri_fields ["contact", "encryption" | @https_fields]
  @contact_schemes ~w(https mailto tel)
  @encryption_schemes ~w(https dns openpgp4fpr)

  @authority_pattern ~r/^(?:[A-Za-z0-9._~!$&'()*+,;=:@\[\]-]|%[0-9A-Fa-f]{2})*$/
  @path_pattern ~r/^(?:[A-Za-z0-9._~!$&'()*+,;=:@\/-]|%[0-9A-Fa-f]{2})*$/
  @query_or_fragment_pattern ~r/^(?:[A-Za-z0-9._~!$&'()*+,;=:@\/?-]|%[0-9A-Fa-f]{2})*$/
  @scheme_pattern ~r/^([A-Za-z][A-Za-z0-9+.-]*):(.*)$/s
  @https_uri_pattern ~r/^https:\/\/[^\/\?#\\]+(?:[\/?#]|$)/i

  @spec validate(String.t(), String.t(), non_neg_integer()) :: Diagnostic.t() | nil
  def validate(field_name, value, line) do
    field = String.downcase(field_name, :ascii)

    if field in @uri_fields do
      validate_uri_field(field, value, line)
    end
  end

  defp validate_uri_field(field, value, line) do
    case Regex.run(@scheme_pattern, value) do
      [_, scheme, scheme_specific] when scheme != "" ->
        scheme = String.downcase(scheme, :ascii)

        if syntactically_valid?(value, scheme, scheme_specific) do
          scheme_diagnostic(field, scheme, line)
        else
          Diagnostic.new(:invalid_uri, line)
        end

      _ ->
        Diagnostic.new(:invalid_uri, line)
    end
  end

  defp scheme_diagnostic("contact", scheme, line) do
    if scheme in @contact_schemes do
      nil
    else
      Diagnostic.new(:invalid_contact_scheme, line)
    end
  end

  defp scheme_diagnostic("encryption", scheme, line) do
    if scheme in @encryption_schemes do
      nil
    else
      Diagnostic.new(:invalid_https_field, line)
    end
  end

  defp scheme_diagnostic(_field, "https", _line), do: nil

  defp scheme_diagnostic(_field, _scheme, line) do
    Diagnostic.new(:invalid_https_field, line)
  end

  defp syntactically_valid?(value, scheme, scheme_specific) do
    valid_rfc3986_structure?(scheme_specific) and
      case scheme do
        "https" -> https_valid?(value)
        _ -> true
      end
  end

  defp https_valid?(value) do
    Regex.match?(@https_uri_pattern, value) and
      case URI.parse(value) do
        %URI{scheme: "https", host: host} when is_binary(host) and host != "" -> true
        _ -> false
      end
  end

  defp valid_rfc3986_structure?(scheme_specific) do
    case String.split(scheme_specific, "#", parts: 2) do
      [before_fragment] ->
        valid_before_fragment?(before_fragment)

      [before_fragment, fragment] ->
        before_fragment != "" and
          fragment != "" and
          not String.contains?(fragment, "#") and
          Regex.match?(@query_or_fragment_pattern, fragment) and
          valid_before_fragment?(before_fragment)
    end
  end

  defp valid_before_fragment?(before_fragment) do
    case String.split(before_fragment, "?", parts: 2) do
      [hierarchy] ->
        valid_hierarchy?(hierarchy)

      [hierarchy, query] ->
        Regex.match?(@query_or_fragment_pattern, query) and valid_hierarchy?(hierarchy)
    end
  end

  defp valid_hierarchy?(hierarchy) do
    if String.starts_with?(hierarchy, "//") do
      case :binary.match(hierarchy, "/", scope: {2, byte_size(hierarchy) - 2}) do
        {path_index, _} ->
          authority = binary_part(hierarchy, 2, path_index - 2)
          path = binary_part(hierarchy, path_index, byte_size(hierarchy) - path_index)

          Regex.match?(@authority_pattern, authority) and Regex.match?(@path_pattern, path)

        :nomatch ->
          authority = binary_part(hierarchy, 2, byte_size(hierarchy) - 2)
          Regex.match?(@authority_pattern, authority)
      end
    else
      hierarchy != "" and Regex.match?(@path_pattern, hierarchy)
    end
  end
end
