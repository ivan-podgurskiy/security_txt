defmodule SecurityTxt.Validator do
  @moduledoc false

  alias SecurityTxt.Diagnostic
  alias SecurityTxt.Expires
  alias SecurityTxt.Field
  alias SecurityTxt.LanguageTag
  alias SecurityTxt.Uri

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

  @type validation_result :: %{
          errors: [Diagnostic.t()],
          recommendations: [Diagnostic.t()],
          notifications: [Diagnostic.t()],
          preferred_languages: [String.t()]
        }

  @spec validate([Field.t()], boolean(), DateTime.t()) :: validation_result()
  def validate(fields, signed, now) do
    contact_fields = fields_named(fields, "contact")
    expires_fields = fields_named(fields, "expires")
    language_fields = fields_named(fields, "preferred-languages")
    encryption_fields = fields_named(fields, "encryption")
    canonical_fields = fields_named(fields, "canonical")
    csaf_fields = fields_named(fields, "csaf")

    {value_errors, preferred_languages, long_expiry_recommendations} =
      validate_field_values(fields, now)

    cardinality_errors =
      cardinality_errors(
        contact_fields,
        expires_fields,
        language_fields
      )

    recommendations =
      long_expiry_recommendations ++
        encryption_recommendation(contact_fields, encryption_fields) ++
        signing_recommendations(signed, canonical_fields) ++
        csaf_recommendations(csaf_fields)

    notifications = unknown_field_notifications(fields)

    %{
      errors: value_errors ++ cardinality_errors,
      recommendations: recommendations,
      notifications: notifications,
      preferred_languages: preferred_languages
    }
  end

  defp validate_field_values(fields, now) do
    Enum.reduce(fields, {[], [], []}, fn field, {errors, languages, long_expiry} ->
      name = String.downcase(field.name, :ascii)

      errors =
        case Uri.validate(field.name, field.value, field.line) do
          nil -> errors
          diagnostic -> [diagnostic | errors]
        end

      {errors, languages, long_expiry} =
        if name == "expires" do
          case Expires.classify(field.value, now) do
            :invalid ->
              {errors ++ [Diagnostic.new(:invalid_expires, field.line)], languages, long_expiry}

            :expired ->
              {errors ++ [Diagnostic.new(:expired, field.line)], languages, long_expiry}

            :long ->
              {errors, languages, long_expiry ++ [Diagnostic.new(:long_expiry, field.line)]}

            :current ->
              {errors, languages, long_expiry}
          end
        else
          {errors, languages, long_expiry}
        end

      if name == "preferred-languages" do
        case LanguageTag.parse_list(field.value) do
          {:ok, tags} ->
            {errors, languages ++ tags, long_expiry}

          :error ->
            {errors ++ [Diagnostic.new(:invalid_lang, field.line)], languages, long_expiry}
        end
      else
        {errors, languages, long_expiry}
      end
    end)
    |> then(fn {errors, languages, long_expiry} ->
      {sort_by_line(errors), languages, long_expiry}
    end)
  end

  defp sort_by_line(diagnostics) do
    Enum.sort_by(diagnostics, fn %{line: line} -> line || 0 end)
  end

  defp cardinality_errors(contact_fields, expires_fields, language_fields) do
    []
    |> maybe_no_contact(contact_fields)
    |> maybe_no_expires(expires_fields)
    |> maybe_multi_expires(expires_fields)
    |> maybe_multi_lang(language_fields)
  end

  defp maybe_no_contact(errors, contact_fields) do
    if contact_fields == [] do
      errors ++ [Diagnostic.new(:no_contact, nil)]
    else
      errors
    end
  end

  defp maybe_no_expires(errors, expires_fields) do
    if expires_fields == [] do
      errors ++ [Diagnostic.new(:no_expires, nil)]
    else
      errors
    end
  end

  defp maybe_multi_expires(errors, expires_fields) do
    if length(expires_fields) > 1 do
      line = Enum.at(expires_fields, 1).line
      errors ++ [Diagnostic.new(:multi_expires, line)]
    else
      errors
    end
  end

  defp maybe_multi_lang(errors, language_fields) do
    if length(language_fields) > 1 do
      line = Enum.at(language_fields, 1).line
      errors ++ [Diagnostic.new(:multi_lang, line)]
    else
      errors
    end
  end

  defp encryption_recommendation(contact_fields, encryption_fields) do
    has_mailto =
      Enum.any?(contact_fields, fn %{value: value} ->
        String.match?(value, ~r/^mailto:/i)
      end)

    if has_mailto and encryption_fields == [] do
      [Diagnostic.new(:no_encryption, nil)]
    else
      []
    end
  end

  defp signing_recommendations(signed, canonical_fields) do
    cond do
      not signed -> [Diagnostic.new(:not_signed, nil)]
      canonical_fields == [] -> [Diagnostic.new(:no_canonical, nil)]
      true -> []
    end
  end

  defp csaf_recommendations(csaf_fields) do
    if length(csaf_fields) > 1 do
      line = Enum.at(csaf_fields, 1).line
      [Diagnostic.new(:multi_csaf, line)]
    else
      []
    end
  end

  defp unknown_field_notifications(fields) do
    Enum.flat_map(fields, fn %{name: name, line: line} ->
      if MapSet.member?(@registered_names, String.downcase(name, :ascii)) do
        []
      else
        [Diagnostic.new(:unknown_field, line)]
      end
    end)
  end

  defp fields_named(fields, name) do
    Enum.filter(fields, &(String.downcase(&1.name, :ascii) == name))
  end
end
