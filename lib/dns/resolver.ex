defmodule Dns.Resolver do
  @moduledoc """
  Send a request packet to a higher DNS server for a response
  """

  @cloudflare {1, 1, 1, 1}
  @google {8, 8, 8, 8}

  defp with_ephemeral_socket(f) do
    {:ok, socket} = :gen_udp.open(0, [:binary, active: false])
    result = f.(socket)
    :gen_udp.close(socket)
    result
  end

  def recurse(packet, host \\ @cloudflare) do
    with_ephemeral_socket(fn socket ->
      encoded_packet = Dns.Packet.Encoder.encode(packet)

      :gen_udp.send(socket, {host, 53}, encoded_packet)

      {:ok, {_ip, _port, packet}} = :gen_udp.recv(socket, 0)

      Dns.Packet.Decoder.decode(packet)
    end)
  end

  def resolve(packet) do
    if packet.header.recursion_desired do
      recurse(packet)
    end
  end
end
