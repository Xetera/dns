defmodule DnsTest do
  use ExUnit.Case
  doctest Dns

  test "greets the world" do
    assert Dns.hello() == :world
  end
end
