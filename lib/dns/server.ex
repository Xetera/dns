defmodule Dns.Server do
  alias Dns.Packet
  alias Dns.Packet.Encoder
  alias Dns.Packet.Decoder

  require Logger
  use GenServer
  @dns_port 53

  defmodule State do
    defstruct [:socket]
  end

  def init(port: port) do
    :gen_udp.open(port, [:binary, active: true])
  end

  def start_link(_port) do
    GenServer.start_link(__MODULE__, port: @dns_port)
  end

  def process_packet(socket, {address, port, bytes}) do
    incoming = Decoder.decode(bytes) |> IO.inspect(label: "incoming message")
    response_header = Packet.Header.to_response(incoming.header)

    auth_response = Dns.Resolver.resolve(incoming)

    response = %Packet{
      incoming
      | header: response_header,
        answers: auth_response.answers,
        additional_records: auth_response.additional_records,
        nameservers: auth_response.nameservers
    }

    out = Encoder.encode(response) |> IO.inspect(label: "response bytes")

    :gen_udp.send(socket, address, port, out)
  end

  def handle_info({:udp, socket, address, port, data}, socket) do
    Logger.info("Got a UDP message")
    spawn(fn -> process_packet(socket, {address, port, data}) end)

    {:noreply, socket}
  end

  def send_response(socket, response) do
    :gen_udp.send(socket, response)
  end
end
