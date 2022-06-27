defmodule Dns.Domain do
  defp parse_host_labels(<<0, rest::binary>>), do: {[], rest}

  defp parse_host_labels(<<length::size(8), label::binary-size(length), rest::binary>>) do
    {labels, rest} = parse_host_labels(rest)
    {[label | labels], rest}
  end

  # resolving pointers
  def resolve(<<3::size(2), offset::size(14), rest::binary>>, raw) do
    <<_leading::offset*8, data::binary>> = raw
    {labels, _} = parse_host_labels(data)
    {labels, rest}
  end

  def resolve(binary, _raw) do
    parse_host_labels(binary)
  end
end
