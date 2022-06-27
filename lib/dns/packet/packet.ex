defmodule Dns.Packet.Question do
  defstruct qname: [],
            qtype: "",
            qclass: ""
end

defmodule Dns.Packet.Resource do
  defstruct name: [],
            type: 0,
            class: 0,
            ttl: 3600,
            rdlength: 0,
            rdata: ""
end

defmodule Dns.Packet do
  # @spec response_code :: number()
  def response_codes,
    do: %{
      ok: 0,
      format_error: 1,
      server_failure: 2,
      name_error: 3,
      not_implemented: 4,
      refused: 5
      # 6 - 15 reserved
    }

  defstruct header: nil,
            # DNS only ever allows for one question
            question: nil,
            answers: [],
            nameservers: [],
            additional_records: [],
            raw: nil

  @type packet_type :: :query | :response

  def from_query_type(:query), do: 0
  def from_query_type(:response), do: 1

  def to_query_type(0), do: :query
  def to_query_type(1), do: :response

  @spec pad_packet(integer() | binary()) :: binary()
  defp pad_packet(elem) do
    bytes =
      if is_binary(elem) do
        elem
      else
        :binary.encode_unsigned(elem)
      end

    pad = 2 - byte_size(bytes)

    if pad > 0 do
      <<0::pad*8, bytes::binary>>
    else
      <<bytes::binary>>
    end
  end
end

defmodule Dns.Packet.Header do
  defstruct id: 0,
            type: :query,
            opcode: 0,
            authoritative_answer: false,
            truncation: false,
            recursion_desired: false,
            recursion_available: false,
            # z is always 3 bits of 0
            # z: 0,
            response_code: Dns.Packet.response_codes().ok

  def to_response(header) do
    %__MODULE__{
      id: header.id,
      type: :response,
      opcode: 0,
      authoritative_answer: false,
      truncation: false,
      recursion_available: true,
      recursion_desired: true,
      response_code: Dns.Packet.response_codes().ok
    }
  end
end
