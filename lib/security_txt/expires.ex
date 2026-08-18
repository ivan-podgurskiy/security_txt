defmodule SecurityTxt.Expires do
  @moduledoc false

  @rfc3339_pattern ~r/^(\d{4})-(\d{2})-(\d{2})[Tt](\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?([Zz]|([+-])(\d{2}):(\d{2}))$/

  @spec parse(String.t()) :: {:ok, DateTime.t()} | :error
  def parse(value) do
    case Regex.run(@rfc3339_pattern, value) do
      [_, year_s, month_s, day_s, hour_s, minute_s, second_s, fraction, _tz | rest] ->
        {offset_sign, offset_hour_s, offset_minute_s} =
          case rest do
            [sign, hour, minute] -> {sign, hour, minute}
            _ -> {nil, nil, nil}
          end

        parse_components(%{
          year_s: year_s,
          month_s: month_s,
          day_s: day_s,
          hour_s: hour_s,
          minute_s: minute_s,
          second_s: second_s,
          fraction: fraction,
          offset_sign: offset_sign,
          offset_hour_s: offset_hour_s,
          offset_minute_s: offset_minute_s
        })

      _ ->
        :error
    end
  end

  @spec classify(String.t(), DateTime.t()) :: :invalid | :expired | :current | :long
  def classify(value, now) do
    case parse(value) do
      {:ok, expiry} ->
        cond do
          DateTime.compare(expiry, now) == :lt -> :expired
          DateTime.compare(expiry, one_calendar_year_after(now)) == :gt -> :long
          true -> :current
        end

      :error ->
        :invalid
    end
  end

  defp parse_components(components) do
    with {year, ""} <- Integer.parse(components.year_s),
         {month, ""} <- Integer.parse(components.month_s),
         {day, ""} <- Integer.parse(components.day_s),
         {hour, ""} <- Integer.parse(components.hour_s),
         {minute, ""} <- Integer.parse(components.minute_s),
         {second, ""} <- Integer.parse(components.second_s),
         offset_hour when is_integer(offset_hour) <-
           parse_offset_hour(components.offset_hour_s),
         offset_minute when is_integer(offset_minute) <-
           parse_offset_minute(components.offset_minute_s),
         true <-
           valid_ranges?(year, month, day, hour, minute, second, offset_hour, offset_minute) do
      leap_second? = second == 60
      constructed_second = if leap_second?, do: 59, else: second
      microsecond = parse_microsecond(components.fraction)

      with true <-
             valid_local_components?(
               year,
               month,
               day,
               hour,
               minute,
               constructed_second,
               microsecond
             ),
           normalized <-
             build_normalized_iso8601(%{
               year: year,
               month: month,
               day: day,
               hour: hour,
               minute: minute,
               second: constructed_second,
               fraction: components.fraction,
               offset_sign: components.offset_sign,
               offset_hour_s: components.offset_hour_s,
               offset_minute_s: components.offset_minute_s
             }),
           {:ok, datetime, _} <- DateTime.from_iso8601(normalized),
           true <-
             calendar_components_round_trip?(%{
               datetime: datetime,
               year: year,
               month: month,
               day: day,
               hour: hour,
               minute: minute,
               second: constructed_second,
               microsecond: microsecond,
               offset_sign: components.offset_sign,
               offset_hour: offset_hour,
               offset_minute: offset_minute
             }) do
        finalize_datetime(datetime, leap_second?)
      else
        _ -> :error
      end
    else
      _ -> :error
    end
  end

  defp finalize_datetime(datetime, true) do
    if possible_positive_leap_second?(datetime) do
      {:ok, DateTime.add(datetime, 1, :second)}
    else
      :error
    end
  end

  defp finalize_datetime(datetime, false), do: {:ok, datetime}

  defp parse_offset_hour(nil), do: 0

  defp parse_offset_hour(value) do
    {hour, ""} = Integer.parse(value)
    hour
  end

  defp parse_offset_minute(nil), do: 0

  defp parse_offset_minute(value) do
    {minute, ""} = Integer.parse(value)
    minute
  end

  defp parse_microsecond(fraction) do
    case fraction do
      "" ->
        {0, 0}

      _ ->
        digits = String.slice(fraction <> "000000", 0, 6)

        case String.to_integer(digits) do
          0 -> {0, 0}
          value -> {value, 6}
        end
    end
  end

  defp valid_ranges?(year, month, day, hour, minute, second, offset_hour, offset_minute) do
    month in 1..12 and
      day in 1..days_in_month(year, month) and
      hour <= 23 and
      minute <= 59 and
      second <= 60 and
      offset_hour <= 23 and
      offset_minute <= 59
  end

  defp valid_local_components?(year, month, day, hour, minute, second, microsecond) do
    {:ok, naive} = NaiveDateTime.new(year, month, day, hour, minute, second, microsecond)

    naive.year == year and
      naive.month == month and
      naive.day == day and
      naive.hour == hour and
      naive.minute == minute and
      naive.second == second and
      naive.microsecond == microsecond
  end

  defp build_normalized_iso8601(components) do
    fraction_part =
      case components.fraction do
        "" -> ""
        _ -> "." <> String.slice(components.fraction <> "000000", 0, 6)
      end

    timezone_part =
      case components.offset_sign do
        nil ->
          "Z"

        sign ->
          sign <> components.offset_hour_s <> ":" <> components.offset_minute_s
      end

    "#{pad4(components.year)}-#{pad2(components.month)}-#{pad2(components.day)}T" <>
      "#{pad2(components.hour)}:#{pad2(components.minute)}:#{pad2(components.second)}" <>
      "#{fraction_part}#{timezone_part}"
  end

  defp calendar_components_round_trip?(components) do
    local = local_datetime(components)

    local.year == components.year and
      local.month == components.month and
      local.day == components.day and
      local.hour == components.hour and
      local.minute == components.minute and
      local.second == components.second and
      elem(local.microsecond, 0) == elem(components.microsecond, 0)
  end

  defp local_datetime(%{offset_sign: nil, datetime: datetime}), do: datetime

  defp local_datetime(%{
         datetime: datetime,
         offset_sign: sign,
         offset_hour: offset_hour,
         offset_minute: offset_minute
       }) do
    offset_minutes = offset_hour * 60 + offset_minute
    offset_minutes = if sign == "-", do: -offset_minutes, else: offset_minutes
    DateTime.add(datetime, offset_minutes, :minute)
  end

  defp possible_positive_leap_second?(datetime) do
    datetime.hour == 23 and
      datetime.minute == 59 and
      datetime.second == 59 and
      ((datetime.month == 6 and datetime.day == 30) or
         (datetime.month == 12 and datetime.day == 31))
  end

  defp one_calendar_year_after(%DateTime{} = value) do
    year = value.year + 1
    month = value.month
    day = min(value.day, days_in_month(year, month))

    %{
      value
      | year: year,
        day: day
    }
  end

  defp days_in_month(year, month) do
    leap_year? = rem(year, 4) == 0 and (rem(year, 100) != 0 or rem(year, 400) == 0)

    cond do
      month == 2 -> if leap_year?, do: 29, else: 28
      month in [4, 6, 9, 11] -> 30
      true -> 31
    end
  end

  defp pad2(value), do: value |> Integer.to_string() |> String.pad_leading(2, "0")
  defp pad4(value), do: value |> Integer.to_string() |> String.pad_leading(4, "0")
end
