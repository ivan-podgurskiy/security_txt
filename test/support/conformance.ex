defmodule Conformance do
  @moduledoc false

  @fixture_version 1

  @serialize_key_map %{
    "comments" => :comments,
    "contact" => :contact,
    "expires" => :expires,
    "acknowledgments" => :acknowledgments,
    "canonical" => :canonical,
    "csaf" => :csaf,
    "encryption" => :encryption,
    "hiring" => :hiring,
    "policy" => :policy,
    "preferredLanguages" => :preferred_languages
  }

  def configure!(path) do
    captured_now = DateTime.utc_now()
    symbols = build_symbols(captured_now)

    fixture =
      path
      |> File.read!()
      |> Jason.decode!()

    version = Map.fetch!(fixture, "version")

    if version != @fixture_version do
      raise "Unsupported conformance version: #{version}"
    end

    :persistent_term.put({__MODULE__, :state}, %{
      path: path,
      captured_now: captured_now,
      symbols: symbols,
      fixture: fixture
    })
  end

  def captured_now do
    state!().captured_now
  end

  def parse_cases do
    Map.fetch!(state!().fixture, "parse")
  end

  def serialize_cases do
    Map.fetch!(state!().fixture, "serialize")
  end

  def fixtures_dir do
    Path.dirname(state!().path)
  end

  def run_parse_case(case) do
    input =
      case Map.get(case, "input") do
        nil ->
          path =
            Map.fetch!(case, "inputFile")
            |> String.replace("real-world/", "real_world/")

          path = Path.join(fixtures_dir(), path)
          File.read!(path)

        template ->
          materialize_text(template)
      end

    comparable(SecurityTxt.parse(input))
  end

  def expected_parse(case) do
    materialize(expected_for_time(case, captured_now()))
  end

  def run_serialize_case(case) do
    options = serialize_options(Map.fetch!(case, "options"))

    if Map.get(case, "throws") do
      try do
        SecurityTxt.serialize(options)
        {:ok, :no_raise}
      rescue
        ArgumentError -> {:error, :argument_error}
      end
    else
      {:ok, SecurityTxt.serialize(options)}
    end
  end

  def expected_serialize(case) do
    if Map.get(case, "throws") do
      :throws
    else
      materialize(Map.fetch!(case, "expected"))
    end
  end

  def comparable(result) do
    %{
      "valid" => result.valid,
      "fields" => normalize_fields(result.fields),
      "contact" => result.contact,
      "expires" => result.expires,
      "acknowledgments" => result.acknowledgments,
      "canonical" => result.canonical,
      "csaf" => result.csaf,
      "encryption" => result.encryption,
      "hiring" => result.hiring,
      "policy" => result.policy,
      "preferredLanguages" => result.preferred_languages,
      "signed" => result.signed,
      "errors" => diagnostic_pairs(result.errors),
      "recommendations" => diagnostic_pairs(result.recommendations),
      "notifications" => diagnostic_pairs(result.notifications)
    }
  end

  def matches_object?(actual, expected) when is_map(expected) do
    Enum.all?(expected, fn {key, expected_value} ->
      actual_value = Map.fetch!(actual, key)
      values_match?(actual_value, expected_value)
    end)
  end

  def values_match?(actual, expected) when is_list(expected) and is_list(actual) do
    actual == expected
  end

  def values_match?(actual, expected) when is_map(expected) and is_map(actual) do
    matches_object?(actual, expected)
  end

  def values_match?(actual, expected), do: actual == expected

  defp normalize_fields(fields) do
    Enum.map(fields, fn field ->
      %{"name" => field.name, "value" => field.value, "line" => field.line}
    end)
  end

  defp state! do
    :persistent_term.get({__MODULE__, :state})
  end

  defp diagnostic_pairs(diagnostics) do
    Enum.map(diagnostics, fn diagnostic ->
      %{"code" => diagnostic.code, "line" => diagnostic.line}
    end)
  end

  defp expected_for_time(case, now) do
    expires_at = Map.get(case, "expiresAt")
    expiry_phases = Map.get(case, "expiryPhases")

    if expires_at && expiry_phases do
      expiry =
        case DateTime.from_iso8601(expires_at) do
          {:ok, datetime, _} -> datetime
          {:ok, datetime} -> datetime
        end
      phase =
        cond do
          DateTime.compare(now, expiry) == :gt ->
            Map.fetch!(expiry_phases, "afterExpiry")

          DateTime.compare(expiry, one_calendar_year_after(now)) == :gt ->
            Map.fetch!(expiry_phases, "beyondOneYear")

          true ->
            Map.fetch!(expiry_phases, "withinOneYear")
        end

      Map.fetch!(case, "expected")
      |> Map.merge(phase)
    else
      Map.fetch!(case, "expected")
    end
  end

  defp one_calendar_year_after(%DateTime{} = value) do
    year = value.year + 1
    month = value.month
    day = min(value.day, days_in_month(year, month))

    %{value | year: year, day: day}
  end

  defp days_in_month(year, month) do
    leap_year? = rem(year, 4) == 0 and (rem(year, 100) != 0 or rem(year, 400) == 0)

    cond do
      month == 2 -> if leap_year?, do: 29, else: 28
      month in [4, 6, 9, 11] -> 30
      true -> 31
    end
  end

  defp build_symbols(captured_now) do
    %{
      "{{past}}" => iso_timestamp(DateTime.add(captured_now, -86_400, :second)),
      "{{within_one_year}}" =>
        iso_timestamp(DateTime.add(captured_now, 30 * 86_400, :second)),
      "{{beyond_one_year}}" => beyond_one_year_iso(captured_now),
      "{{beyond_one_year_lower_z}}" =>
        String.replace_suffix(beyond_one_year_iso(captured_now), "Z", "z")
    }
  end

  defp beyond_one_year_iso(%DateTime{} = now) do
    year = now.year + 2
    month = now.month
    day = min(now.day, days_in_month(year, month))

    {:ok, naive} =
      NaiveDateTime.new(year, month, day, now.hour, now.minute, now.second, now.microsecond)

    naive
    |> DateTime.from_naive!("Etc/UTC")
    |> iso_timestamp()
  end

  defp iso_timestamp(%DateTime{} = datetime) do
    datetime
    |> DateTime.to_iso8601()
    |> strip_zero_fraction()
  end

  defp strip_zero_fraction(iso) do
    iso
    |> String.replace_suffix(".000000Z", "Z")
    |> String.replace_suffix(".000Z", "Z")
  end

  defp materialize(value) when is_binary(value) do
    symbols = state!().symbols

    Enum.reduce(symbols, value, fn {symbol, replacement}, acc ->
      String.replace(acc, symbol, replacement)
    end)
  end

  defp materialize(value) when is_list(value) do
    Enum.map(value, &materialize/1)
  end

  defp materialize(value) when is_map(value) do
    cond do
      Map.has_key?(value, "parts") ->
        materialize_text(value)

      Map.has_key?(value, "repeatArray") and is_integer(Map.get(value, "count")) ->
        repeat = materialize(Map.fetch!(value, "repeatArray"))
        count = Map.fetch!(value, "count")
        Enum.map(1..count, fn _ -> repeat end)

      true ->
        Map.new(value, fn {key, item} -> {key, materialize(item)} end)
    end
  end

  defp materialize(value), do: value

  defp materialize_text(template) when is_binary(template), do: materialize(template)

  defp materialize_text(%{"parts" => parts}) do
    parts
    |> Enum.map(fn
      %{"text" => text} -> materialize(text)
      %{"repeat" => repeat, "count" => count} -> String.duplicate(materialize(repeat), count)
      _ -> raise "Invalid conformance text part"
    end)
    |> Enum.join("")
  end

  defp serialize_options(options) when is_map(options) do
    options
    |> Map.new(fn {key, value} ->
      {Map.fetch!(@serialize_key_map, key), materialize(value)}
    end)
    |> Keyword.new()
  end
end
