defmodule Dns.Packet.Encoder do
  require Logger

  @moduledoc """
  Encoding for DNS packets that turns them from structred data into binary
  """

  defp bool_to_int(true), do: 1
  defp bool_to_int(false), do: 0
  defp bool_to_int(a), do: a

  def encode(packet) do
    require IEx

    %Dns.Packet{
      header: header,
      question: question,
      answers: answers,
      nameservers: nameservers,
      additional_records: additional_records
    } = packet

    %Dns.Packet.Header{
      id: id,
      type: qr,
      opcode: opcode,
      authoritative_answer: aa,
      truncation: tc,
      recursion_desired: rd,
      recursion_available: ra,
      response_code: rc
    } = header

    flags =
      :binary.decode_unsigned(
        <<Dns.Packet.from_query_type(qr)::size(1), opcode::size(4), bool_to_int(aa)::size(1),
          bool_to_int(tc)::size(1), bool_to_int(rd)::size(1), bool_to_int(ra)::size(1),
          0::size(3), rc::size(4)>>
      )

    header = <<
      id::size(16),
      flags::size(16),
      # there should only ever be 1 question (de)serialized
      1::size(16),
      length(answers)::size(16),
      length(nameservers)::size(16),
      length(additional_records)::size(16)
    >>

    question_bytes = encode_question(question)

    parts =
      List.flatten([answers, nameservers, additional_records])
      |> Enum.map(&encode_resource/1)
      |> concat()

    parts =
      if is_list(parts) do
        :binary.list_to_bin(parts)
      else
        parts
      end

    header <> question_bytes <> parts
  end

  defp encode_resource(resource) do
    %Dns.Packet.Resource{
      name: name,
      type: type,
      class: class,
      ttl: ttl,
      rdlength: rdlength,
      rdata: rdata
    } = resource

    serialize_labels(name) <>
      <<
        type::size(16),
        class::size(16),
        ttl::size(32),
        rdlength::size(16),
        rdata::rdlength*8
      >>
  end

  defp encode_question(question) do
    %Dns.Packet.Question{
      qname: qname,
      qtype: qtype,
      qclass: qclass
    } = question

    labels = serialize_labels(qname)

    labels <>
      <<
        qtype::size(16),
        qclass::size(16)
      >>
  end

  defp serialize_labels(labels) do
    out =
      labels
      |> Enum.flat_map(fn part -> [String.length(part), to_charlist(part)] end)
      |> :binary.list_to_bin()

    # null byte at the end to show the end of the domain
    out <> <<0>>
  end

  defp concat([]) do
    []
  end

  defp concat(sections) do
    sections |> Enum.reduce(fn elem, acc -> elem <> acc end)
  end
end
