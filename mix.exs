defmodule SecurityTxt.MixProject do
  use Mix.Project

  @version "1.0.0"
  @source_url "https://github.com/ivan-podgurskiy/security_txt"

  def project do
    [
      app: :security_txt,
      version: @version,
      elixir: "~> 1.14",
      deps: deps(),
      name: "SecurityTxt",
      description: "Parse, validate, and serialize RFC 9116 security.txt files in Elixir.",
      package: package(),
      source_url: @source_url,
      docs: docs(),
      test_ignore_filters: [&String.starts_with?(&1, "test/support/")],
      test_coverage: [summary: [threshold: 100]],
      dialyzer: [
        plt_add_apps: [:ex_unit, :mix],
        plt_local_path: "priv/plts/local.plt",
        plt_core_path: "priv/plts/core.plt"
      ]
    ]
  end

  defp deps do
    [
      {:stream_data, "~> 1.1", only: [:dev, :test]},
      {:jason, "~> 1.4", only: [:dev, :test], runtime: false},
      {:ex_doc, "~> 0.34", only: :dev, runtime: false},
      {:credo, "~> 1.7", only: :dev, runtime: false},
      {:dialyxir, "~> 1.4", only: [:dev, :test], runtime: false}
    ]
  end

  defp package do
    [
      files: ~w(lib .formatter.exs mix.exs README.md LICENSE CHANGELOG.md THIRD_PARTY_NOTICES.md),
      licenses: ["MIT"],
      links: %{"GitHub" => @source_url},
      maintainers: ["Ivan Podgurskiy"]
    ]
  end

  defp docs do
    [
      main: "SecurityTxt",
      source_ref: "v#{@version}",
      source_url: @source_url
    ]
  end
end
