defmodule SecurityTxt.PropertyTest do
  use ExUnit.Case
  use ExUnitProperties

  @alphabet [
    "",
    "a",
    "Z",
    "0",
    ":",
    "#",
    " ",
    "\t",
    "\r",
    "\n",
    "\0",
    "\uFEFF",
    "/",
    "%",
    "-",
    ",",
    "é",
    "😀"
  ]

  defp next_xorshift(state) do
    state =
      state
      |> Bitwise.bxor(Bitwise.bsl(state, 13))
      |> Bitwise.bxor(Bitwise.bsr(state, 17))
      |> Bitwise.bxor(Bitwise.bsl(state, 5))
      |> Bitwise.band(0xFFFFFFFF)

    {state, state}
  end

  defp bounded_arbitrary_string_generator do
    gen all(seed <- integer(0..0xFFFFFFFF)) do
      {length, state} = next_xorshift(seed)
      length = rem(length, 257)

      chars =
        if length == 0 do
          []
        else
          Enum.map(1..length, fn _ ->
            {value, _state} = next_xorshift(state)
            Enum.at(@alphabet, rem(value, length(@alphabet)))
          end)
        end

      Enum.join(chars)
    end
  end

  defp choose(values, state) do
    {value, state} = next_xorshift(state)
    {Enum.at(values, rem(value, length(values))), state}
  end

  defp random_case(value, state) do
    {chars, state} =
      value
      |> String.graphemes()
      |> Enum.map_reduce(state, fn char, current_state ->
        if Regex.match?(~r/[A-Za-z]/, char) do
          {bit, current_state} = next_xorshift(current_state)

          if rem(bit, 2) == 1 do
            {String.upcase(char), current_state}
          else
            {String.downcase(char), current_state}
          end
        else
          {char, current_state}
        end
      end)

    {Enum.join(chars), state}
  end

  defp random_options(index, expires, state) do
    contact_sets = [
      ["https://example.com/report/#{index}"],
      [
        "mailto:security#{index}@example.com",
        "tel:+1-201-555-#{String.pad_leading(Integer.to_string(index), 4, "0")}"
      ],
      [
        "tel:+44-20-7946-#{String.pad_leading(Integer.to_string(index), 4, "0")}",
        "https://example.com/report/#{index}"
      ]
    ]

    {contact_set, state} = choose(contact_sets, state)
    contact = contact_set

    {contact_bit, state} = next_xorshift(state)

    contact =
      if length(contact) == 1 and rem(contact_bit, 2) == 1 do
        hd(contact)
      else
        contact
      end

    {expires_bit, state} = next_xorshift(state)

    expires_value =
      if rem(expires_bit, 2) == 1 do
        {:ok, datetime, _} = DateTime.from_iso8601(expires)
        datetime
      else
        expires
      end

    options = [contact: contact, expires: expires_value]
    {bit, state} = next_xorshift(state)

    options =
      if rem(bit, 2) == 1 do
        Keyword.put(options, :comments, [
          "Generated case #{index}",
          "Seeded sequence #{Integer.to_string(index, 16)}"
        ])
      else
        options
      end

    {bit, state} = next_xorshift(state)

    options =
      if rem(bit, 2) == 1 do
        ack_choices = [
          "https://example.com/thanks/#{index}",
          [
            "https://example.com/thanks/#{index}/first",
            "https://example.com/thanks/#{index}/second"
          ]
        ]

        {ack, _state} = choose(ack_choices, state)
        Keyword.put(options, :acknowledgments, ack)
      else
        options
      end

    {bit, state} = next_xorshift(state)

    options =
      if rem(bit, 2) == 1 do
        Keyword.put(
          options,
          :canonical,
          "https://example.com/.well-known/security-#{index}.txt"
        )
      else
        options
      end

    {bit, state} = next_xorshift(state)

    options =
      if rem(bit, 2) == 1 do
        csaf_choices = [
          "https://example.com/csaf/#{index}/provider-metadata.json",
          [
            "https://example.com/csaf/#{index}/one.json",
            "https://example.com/csaf/#{index}/two.json"
          ]
        ]

        {csaf, _state} = choose(csaf_choices, state)
        Keyword.put(options, :csaf, csaf)
      else
        options
      end

    {bit, state} = next_xorshift(state)

    options =
      if rem(bit, 2) == 1 do
        enc_choices = [
          "https://example.com/key/#{index}.asc",
          "dns:key-#{index}.example.com",
          "openpgp4fpr:#{String.pad_leading(Integer.to_string(index, 16), 16, "0")}"
        ]

        {encryption, _state} = choose(enc_choices, state)
        Keyword.put(options, :encryption, encryption)
      else
        options
      end

    {bit, state} = next_xorshift(state)

    options =
      if rem(bit, 2) == 1 do
        Keyword.put(options, :hiring, "https://example.com/jobs/#{index}")
      else
        options
      end

    {bit, state} = next_xorshift(state)

    options =
      if rem(bit, 2) == 1 do
        Keyword.put(options, :policy, [
          "https://example.com/policy/#{index}/first",
          "https://example.com/policy/#{index}/second"
        ])
      else
        options
      end

    {bit, state} = next_xorshift(state)

    options =
      if rem(bit, 2) == 1 do
        language_choices = [
          ["en"],
          ["en-US", "zh-Hant"],
          ["i-klingon", "x-acme"],
          ["de-CH-1901", "sl-rozaj-biske"]
        ]

        {languages, state} = choose(language_choices, state)
        {lang_bit, _state} = next_xorshift(state)

        preferred_languages =
          if length(languages) == 1 and rem(lang_bit, 2) == 1 do
            hd(languages)
          else
            languages
          end

        Keyword.put(options, :preferred_languages, preferred_languages)
      else
        options
      end

    {options, state}
  end

  defp strings(value) do
    case value do
      nil -> []
      value when is_binary(value) -> [value]
      value when is_list(value) -> value
    end
  end

  defp serialized_expiry(value) do
    case value do
      %DateTime{} = datetime ->
        datetime
        |> DateTime.to_iso8601()
        |> String.replace_suffix(".000Z", "Z")

      value when is_binary(value) ->
        value
    end
  end

  defp expected_fields(options) do
    comments = Keyword.get(options, :comments, [])
    line = length(comments) + 1

    {fields, line} =
      {[], line}
      |> add_fields("Contact", strings(Keyword.get(options, :contact)))
      |> add_fields("Expires", [serialized_expiry(Keyword.fetch!(options, :expires))])
      |> add_fields("Acknowledgments", strings(Keyword.get(options, :acknowledgments)))
      |> add_fields("Canonical", strings(Keyword.get(options, :canonical)))
      |> add_fields("CSAF", strings(Keyword.get(options, :csaf)))
      |> add_fields("Encryption", strings(Keyword.get(options, :encryption)))
      |> add_fields("Hiring", strings(Keyword.get(options, :hiring)))
      |> add_fields("Policy", strings(Keyword.get(options, :policy)))

    languages = strings(Keyword.get(options, :preferred_languages))

    if languages == [] do
      fields
    else
      fields ++ [%{name: "Preferred-Languages", value: Enum.join(languages, ", "), line: line}]
    end
  end

  defp add_fields({fields, line}, name, values) do
    Enum.reduce(values, {fields, line}, fn value, {acc, current_line} ->
      field = %{name: name, value: value, line: current_line}
      {acc ++ [field], current_line + 1}
    end)
  end

  defp diagnostic_pairs(diagnostics) do
    Enum.map(diagnostics, fn diagnostic -> %{code: diagnostic.code, line: diagnostic.line} end)
  end

  defp expected_recommendations(options, fields) do
    recommendations = []

    recommendations =
      if Enum.any?(strings(Keyword.get(options, :contact)), &String.match?(&1, ~r/^mailto:/i)) and
           strings(Keyword.get(options, :encryption)) == [] do
        recommendations ++ [%{code: "no_encryption", line: nil}]
      else
        recommendations
      end

    recommendations = recommendations ++ [%{code: "not_signed", line: nil}]

    csaf_values = strings(Keyword.get(options, :csaf))

    if length(csaf_values) > 1 do
      csaf_fields = Enum.filter(fields, &(&1.name == "CSAF"))
      second = Enum.at(csaf_fields, 1)

      recommendations ++ [%{code: "multi_csaf", line: second.line}]
    else
      recommendations
    end
  end

  defp randomize_registered_field_case(content, state) do
    Process.put(:property_prng_state, state)

    result =
      Regex.replace(
        ~r/^(Contact|Expires|Acknowledgments|Canonical|CSAF|Encryption|Hiring|Policy|Preferred-Languages):/m,
        content,
        fn match ->
          name = String.trim_trailing(match, ":")
          current_state = Process.get(:property_prng_state)
          {cased, new_state} = random_case(name, current_state)
          Process.put(:property_prng_state, new_state)
          cased <> ":"
        end
      )

    {result, Process.get(:property_prng_state)}
  end

  property "bounded arbitrary strings never crash the parser" do
    check all(input <- bounded_arbitrary_string_generator(), max_runs: 1_000) do
      assert %{} = SecurityTxt.parse(input)
    end
  end

  property "valid option objects round trip across casing and line endings" do
    expires =
      DateTime.utc_now()
      |> DateTime.add(30 * 86_400, :second)
      |> DateTime.to_iso8601()

    check all(index <- integer(0..499), max_runs: 500) do
      {options, _state} = random_options(index, expires, index + 1)

      output = SecurityTxt.serialize(options)
      parsed = SecurityTxt.parse(output)
      fields = expected_fields(options)

      expected_state = %{
        contact: strings(Keyword.get(options, :contact)),
        expires: serialized_expiry(Keyword.fetch!(options, :expires)),
        acknowledgments: strings(Keyword.get(options, :acknowledgments)),
        canonical: strings(Keyword.get(options, :canonical)),
        csaf: strings(Keyword.get(options, :csaf)),
        encryption: strings(Keyword.get(options, :encryption)),
        hiring: strings(Keyword.get(options, :hiring)),
        policy: strings(Keyword.get(options, :policy)),
        preferred_languages: strings(Keyword.get(options, :preferred_languages))
      }

      comments = Keyword.get(options, :comments, [])

      assert parsed.errors == []
      assert parsed.valid
      assert Map.take(parsed, Map.keys(expected_state)) == expected_state
      assert parsed.fields == fields
      assert parsed.signed == false
      assert parsed.notifications == []
      assert diagnostic_pairs(parsed.recommendations) == expected_recommendations(options, fields)

      comment_lines = Enum.map(comments, &"# #{&1}")

      assert String.split(output, "\n", trim: false) |> Enum.take(length(comments)) ==
               comment_lines

      case_randomized =
        SecurityTxt.parse(
          randomize_registered_field_case(output, index + 1)
          |> elem(0)
        )

      assert Map.take(case_randomized, Map.keys(expected_state)) == expected_state
      assert case_randomized.valid
      assert case_randomized.signed == false
      assert case_randomized.errors == []
      assert case_randomized.notifications == []

      assert Enum.map(case_randomized.fields, fn field ->
               %{name: String.downcase(field.name), value: field.value, line: field.line}
             end) ==
               Enum.map(fields, fn field ->
                 %{name: String.downcase(field.name), value: field.value, line: field.line}
               end)

      assert diagnostic_pairs(case_randomized.recommendations) ==
               expected_recommendations(options, fields)

      crlf_input = String.replace(output, "\n", "\r\n")
      crlf = SecurityTxt.parse(crlf_input)
      assert crlf == parsed
    end
  end
end
