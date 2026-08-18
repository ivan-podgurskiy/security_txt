#!/usr/bin/env escript

expected =
  "8e627e34c02ed596d24165a33f6dce498c386b745cee2f23d4084e1212b59e8c"

fixture =
  Path.join([__DIR__, "..", "test", "fixtures", "conformance.json"])
  |> Path.expand()
  |> File.read!()

actual =
  :crypto.hash(:sha256, fixture)
  |> Base.encode16(case: :lower)

if actual != expected do
  IO.puts(:stderr, "Conformance fixture SHA-256 mismatch:")
  IO.puts(:stderr, "expected #{expected}")
  IO.puts(:stderr, "actual   #{actual}")
  System.halt(1)
else
  IO.puts("Conformance fixture SHA-256: #{actual}")
end
