defmodule Dns.Packet.Decoder do
  require Logger

  defp int_to_bool(1), do: true
  defp int_to_bool(0), do: false
  defp int_to_bool(a), do: a

  @spec decode(binary()) :: Dns.Packet
  def decode(packet) do
    require IEx
    {:ok, header, interim, rest} = header(packet)
    {questions, rest} = decode_until_done(&question/1, {rest, packet}, interim.qd_count)
    {answers, rest} = decode_until_done(&resource/1, {rest, packet}, interim.an_count)
    {namespaces, rest} = decode_until_done(&resource/1, {rest, packet}, interim.ns_count)
    {additional_records, rest} = decode_until_done(&resource/1, {rest, packet}, interim.ar_count)

    question_length = interim.qd_count

    if question_length != 1 do
      Logger.warn(
        "Packet with ID (#{header.id}) did not have a question length of 1 (#{question_length})"
      )
    end

    remaining_byte_len = byte_size(rest)

    if remaining_byte_len > 0 do
      Logger.warn(
        "Didn't parse all the content from packet ID: #{header.id}. Missing bytes: #{remaining_byte_len}\nCould be due to eDNS."
      )
    end

    [first_question] = questions
    # {questions, rest} = decode_until_done(&question/1, rest, interm.qd_count)
    %Dns.Packet{
      header: header,
      question: first_question,
      answers: answers,
      nameservers: namespaces,
      additional_records: additional_records,
      raw: packet
    }
  end

  defp decode_until_done(_f, {"", _packet}, 0) do
    {[], ""}
  end

  defp decode_until_done(_f, {rest, _packet}, 0) do
    {[], rest}
  end

  defp decode_until_done(f, {rest, raw}, i) do
    {:ok, result, rest} = f.({rest, raw})
    {results, rest} = decode_until_done(f, {rest, raw}, i - 1)
    {[result | results], rest}
  end

  # private
  # Needed to decide how much to parse into lists without
  # causing a leaky abstraction
  defmodule Interim do
    defstruct qd_count: 1,
              an_count: 0,
              ns_count: 0,
              ar_count: 0
  end

  @spec question({binary(), binary()}) :: {:ok, Dns.Packet.Question, binary()}
  def question({binary, raw}) do
    # require IEx
    # IEx.pry()
    {labels, rest} = Dns.Domain.resolve(binary, raw)

    <<type::size(16), class::size(16), rest::binary>> = rest

    q = %Dns.Packet.Question{
      qname: labels,
      qtype: type,
      qclass: class
    }

    {:ok, q, rest}
  end

  @spec header(binary()) ::
          {:ok, Dns.Packet.Header, Dns.Packet.Decoder.Interim, binary()} | {:error, any()}
  defp header(binary) do
    <<id::size(16), flags::size(16), qd_count::size(16), an_count::size(16), ns_count::size(16),
      ar_count::size(16), rest::binary>> = binary

    <<
      qr::size(1),
      opcode::size(4),
      aa::size(1),
      tc::size(1),
      rd::size(1),
      ra::size(1),
      # z should be zeros but it's good to future-proof things
      # instead of hardcoding 0::size(3)
      _z::size(3),
      rcode::size(4)
    >> = :binary.encode_unsigned(flags)

    interim = %Dns.Packet.Decoder.Interim{
      qd_count: qd_count,
      an_count: an_count,
      ns_count: ns_count,
      ar_count: ar_count
    }

    {:ok,
     %Dns.Packet.Header{
       id: id,
       type:
         if qr == 0 do
           :query
         else
           :response
         end,
       opcode: opcode,
       authoritative_answer: int_to_bool(aa),
       truncation: int_to_bool(tc),
       recursion_desired: int_to_bool(rd),
       recursion_available: int_to_bool(ra),
       response_code: rcode
       #  header_flags: flags,
     }, interim, rest}
  end

  def resource({binary, raw}) do
    {name, rest} = Dns.Domain.resolve(binary, raw)

    <<type::size(16), class::size(16), ttl::size(32), rdlength::size(16), rd::rdlength*8,
      rest::binary>> = rest

    {:ok,
     %Dns.Packet.Resource{
       name: name,
       type: type,
       class: class,
       ttl: ttl,
       rdlength: rdlength,
       rdata: rd
     }, rest}
  end
end
