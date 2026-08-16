defmodule SecurityTxtTest do
  use ExUnit.Case, async: true

  doctest SecurityTxt

  test "exports the package version through Mix metadata" do
    assert Mix.Project.config()[:app] == :security_txt
    assert Mix.Project.config()[:version] == "1.0.0"
  end
end
