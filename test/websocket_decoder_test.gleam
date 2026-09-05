import gleam/bit_array
import gleam/int
import gleam/string
import gramps/websocket
import gramps/websocket/decoder

fn bounded(frame: Int, message: Int) -> decoder.Decoder {
  let assert Ok(state) = decoder.new(frame, message)
    as "positive fixture limits"
  state
}

pub fn refuses_invalid_limits_test() {
  assert decoder.new(0, 1) == Error(Nil)
  assert decoder.new(1, -1) == Error(Nil)
}

pub fn rejects_huge_declared_frame_before_mask_or_payload_arrives_test() {
  let state = bounded(8, 16)
  let assert Ok(decoder.More(state)) = decoder.next(state, <<0x81, 0xff>>)
    as "extended length is incomplete"
  assert decoder.next(state, <<1_000_000_000:64>>)
    == Error(decoder.FrameTooLarge)
}

pub fn rejects_declared_message_before_payload_arrives_test() {
  assert decoder.next(bounded(32, 8), <<0x81, 9>>)
    == Error(decoder.MessageTooLarge)
}

pub fn extended_lengths_are_checked_before_body_and_decode_at_the_limit_test() {
  assert decoder.next(bounded(125, 1000), <<0x82, 126, 126:16>>)
    == Error(decoder.FrameTooLarge)
  let medium = bit_array.from_string(string.repeat("a", 126))
  let assert Ok(decoder.Frame(
    websocket.Data(websocket.BinaryFrame(actual)),
    _,
    <<>>,
  )) = decoder.next(bounded(126, 126), <<0x82, 126, 126:16, medium:bits>>)
    as "a 16-bit length admits exactly its configured byte budget"
  assert actual == medium
  let large = bit_array.from_string(string.repeat("b", 65_536))
  let assert Ok(decoder.Frame(
    websocket.Data(websocket.BinaryFrame(actual)),
    _,
    <<>>,
  )) =
    decoder.next(bounded(65_536, 65_536), <<0x82, 127, 65_536:64, large:bits>>)
    as "a 64-bit length admits exactly its configured byte budget"
  assert actual == large
}

pub fn rejects_compression_before_inflate_test() {
  assert decoder.next(bounded(32, 32), <<0xc1, 0xff>>)
    == Error(decoder.CompressionUnsupported)
}

pub fn fragment_budget_survives_tcp_boundaries_and_control_frames_test() {
  let state = bounded(8, 10)
  let assert Ok(decoder.More(state)) =
    decoder.next(state, <<0x01, 6, "123456">>)
    as "first text fragment is retained"
  let assert Ok(decoder.Frame(
    websocket.Control(websocket.PingFrame(<<"x">>)),
    state,
    <<>>,
  )) = decoder.next(state, <<0x89, 1, "x">>)
    as "control frames do not complete the text message"
  assert decoder.next(state, <<0x80, 5>>) == Error(decoder.MessageTooLarge)
}

pub fn fragments_at_the_exact_limit_form_one_message_test() {
  let state = bounded(6, 10)
  let assert Ok(decoder.More(state)) =
    decoder.next(state, <<0x01, 6, "123456">>)
    as "first fragment fits its frame budget"
  let assert Ok(decoder.More(state)) = decoder.next(state, <<0x80, 4, "78">>)
    as "a partial continuation remains bounded"
  let assert Ok(decoder.Frame(
    websocket.Data(websocket.TextFrame(text)),
    state,
    <<>>,
  )) = decoder.next(state, <<"90">>)
    as "the message completes exactly at its byte budget"
  assert text == <<"1234567890">>
  let assert Ok(decoder.Frame(
    websocket.Data(websocket.BinaryFrame(<<1, 2>>)),
    _,
    <<>>,
  )) = decoder.next(state, <<0x82, 2, 1, 2>>)
    as "the next message receives a fresh budget"
}

pub fn one_result_leaves_later_frames_unconsumed_test() {
  let later = <<0x81, 2, "bb">>
  let assert Ok(decoder.Frame(
    websocket.Data(websocket.TextFrame(<<"aa">>)),
    state,
    rest,
  )) = decoder.next(bounded(2, 2), <<0x81, 2, "aa", later:bits>>)
    as "the caller processes a frame before decoding later input"
  assert rest == later
  let assert Ok(decoder.Frame(
    websocket.Data(websocket.TextFrame(<<"bb">>)),
    _,
    <<>>,
  )) = decoder.next(state, rest)
    as "the caller explicitly advances through remaining frames"
}

pub fn split_masked_message_at_every_byte_boundary_test() {
  // A zero mask keeps the expected body readable while exercising the full
  // mask header and every incomplete-header/payload boundary.
  let frame = <<0x81, 0x85, 0, 0, 0, 0, "hello">>
  int.range(
    from: 0,
    to: bit_array.byte_size(frame) - 1,
    with: Nil,
    run: fn(_, split) {
      let assert Ok(first) = bit_array.slice(frame, 0, split)
        as "prefix split lies inside the fixture"
      let assert Ok(last) =
        bit_array.slice(frame, split, bit_array.byte_size(frame) - split)
        as "suffix split lies inside the fixture"
      let assert Ok(decoder.More(state)) = decoder.next(bounded(5, 5), first)
        as "every strict prefix requires more input"
      let assert Ok(decoder.Frame(
        websocket.Data(websocket.TextFrame(<<"hello">>)),
        _,
        <<>>,
      )) = decoder.next(state, last)
        as "every split reconstructs the same masked message"
      Nil
    },
  )
}

pub fn rejects_invalid_fragment_sequences_and_control_lengths_test() {
  let state = bounded(256, 512)
  assert decoder.next(state, <<0x80, 0>>) == Error(decoder.InvalidFrame)
  assert decoder.next(state, <<0x09, 0>>) == Error(decoder.InvalidFrame)
  assert decoder.next(state, <<0x89, 126>>) == Error(decoder.InvalidFrame)
  let assert Ok(decoder.More(state)) = decoder.next(state, <<0x01, 0>>)
    as "an empty nonfinal fragment still starts a message"
  assert decoder.next(state, <<0x81, 0>>) == Error(decoder.InvalidFrame)
}
