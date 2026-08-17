defmodule SecurityTxt.OpenPgpTest do
  use ExUnit.Case, async: true

  alias SecurityTxt.OpenPgp

  test "extracts cleartext and reverses dash escaping" do
    lines = [
      %{number: 1, text: "-----BEGIN PGP SIGNED MESSAGE-----"},
      %{number: 2, text: "Hash: SHA256"},
      %{number: 3, text: ""},
      %{number: 4, text: "- - Contact: mailto:a@example.com"},
      %{number: 5, text: "-----BEGIN PGP SIGNATURE-----"},
      %{number: 6, text: "abc"},
      %{number: 7, text: "-----END PGP SIGNATURE-----"}
    ]

    assert OpenPgp.extract(lines) == %{
             signed: true,
             lines: [%{number: 4, text: "- Contact: mailto:a@example.com"}]
           }
  end

  test "accepts multiple Hash headers" do
    lines = [
      %{number: 1, text: "-----BEGIN PGP SIGNED MESSAGE-----"},
      %{number: 2, text: "Hash: SHA256"},
      %{number: 3, text: "Hash: SHA512"},
      %{number: 4, text: ""},
      %{number: 5, text: "Contact: mailto:a@example.com"},
      %{number: 6, text: "-----BEGIN PGP SIGNATURE-----"},
      %{number: 7, text: "sig"},
      %{number: 8, text: "-----END PGP SIGNATURE-----"}
    ]

    assert OpenPgp.extract(lines) == %{
             signed: true,
             lines: [%{number: 5, text: "Contact: mailto:a@example.com"}]
           }
  end

  test "preserves original cleartext line numbers" do
    lines = [
      %{number: 1, text: "-----BEGIN PGP SIGNED MESSAGE-----"},
      %{number: 2, text: "Hash: SHA256"},
      %{number: 3, text: ""},
      %{number: 10, text: "Contact: mailto:a@example.com"},
      %{number: 11, text: "Expires: 2030-01-01T00:00:00Z"},
      %{number: 12, text: "-----BEGIN PGP SIGNATURE-----"},
      %{number: 13, text: "sig"},
      %{number: 14, text: "-----END PGP SIGNATURE-----"}
    ]

    assert OpenPgp.extract(lines) == %{
             signed: true,
             lines: [
               %{number: 10, text: "Contact: mailto:a@example.com"},
               %{number: 11, text: "Expires: 2030-01-01T00:00:00Z"}
             ]
           }
  end

  test "returns unsigned input when blank separator line is missing" do
    lines = [
      %{number: 1, text: "-----BEGIN PGP SIGNED MESSAGE-----"},
      %{number: 2, text: "Hash: SHA256"},
      %{number: 3, text: "Contact: mailto:a@example.com"},
      %{number: 4, text: "-----BEGIN PGP SIGNATURE-----"},
      %{number: 5, text: "sig"},
      %{number: 6, text: "-----END PGP SIGNATURE-----"}
    ]

    assert OpenPgp.extract(lines) == %{signed: false, lines: lines}
  end

  test "returns unsigned input when begin signature marker is missing" do
    lines = [
      %{number: 1, text: "-----BEGIN PGP SIGNED MESSAGE-----"},
      %{number: 2, text: "Hash: SHA256"},
      %{number: 3, text: ""},
      %{number: 4, text: "Contact: mailto:a@example.com"}
    ]

    assert OpenPgp.extract(lines) == %{signed: false, lines: lines}
  end

  test "returns unsigned input when end signature marker is missing" do
    lines = [
      %{number: 1, text: "-----BEGIN PGP SIGNED MESSAGE-----"},
      %{number: 2, text: "Hash: SHA256"},
      %{number: 3, text: ""},
      %{number: 4, text: "Contact: mailto:a@example.com"},
      %{number: 5, text: "-----BEGIN PGP SIGNATURE-----"},
      %{number: 6, text: "sig"}
    ]

    assert OpenPgp.extract(lines) == %{signed: false, lines: lines}
  end

  test "returns unsigned for marker-like document without valid envelope" do
    lines = [
      %{number: 1, text: "Contact: mailto:a@example.com"},
      %{number: 2, text: "-----BEGIN PGP SIGNED MESSAGE-----"},
      %{number: 3, text: "Hash: SHA256"},
      %{number: 4, text: ""},
      %{number: 5, text: "Expires: 2030-01-01T00:00:00Z"},
      %{number: 6, text: "-----BEGIN PGP SIGNATURE-----"},
      %{number: 7, text: "sig"},
      %{number: 8, text: "-----END PGP SIGNATURE-----"}
    ]

    assert OpenPgp.extract(lines) == %{signed: false, lines: lines}
  end
end
