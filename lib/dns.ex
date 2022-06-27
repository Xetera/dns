defmodule Dns do
  use Application

  def main do
    start("", "")
  end

  def start(_type, _args) do
    IO.puts("Starting DNS server")

    opts = [strategy: :one_for_all, name: Dns.Server.Supervisor]
    Supervisor.start_link([Dns.Server], opts)
  end
end
