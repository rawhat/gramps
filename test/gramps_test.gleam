import gleam/bit_array
import gleam/bytes_builder
import gleam/http.{Http}
import gleam/http/request
import gleam/http/response
import gleam/option.{None, Some}
import gleeunit
import gleeunit/should
import gramps/debug
import gramps/http as gramps_http
import gramps/websocket

pub fn main() {
  gleeunit.main()
}

pub fn it_should_encode_text_frame_without_mask_test() {
  websocket.to_text_frame("hello, world!", None, None)
  |> should.equal(
    bytes_builder.from_bit_array(<<
      129, 13, 104, 101, 108, 108, 111, 44, 32, 119, 111, 114, 108, 100, 33,
    >>),
  )
}

pub fn it_should_make_empty_pong_frame_with_mask_test() {
  let mask = <<
    22, 172, 3, 21, 180, 229, 185, 224, 250, 191, 218, 236, 236, 22, 253, 17,
    194, 133, 231, 254, 174, 158, 121, 106, 101, 253, 1, 21, 207, 148, 72, 20,
  >>
  websocket.frame_to_bytes_builder(
    websocket.Control(websocket.PongFrame(0, <<>>)),
    Some(mask),
  )
  |> should.equal(
    bytes_builder.from_bit_array(<<1:1, 0:3, 10:4, 1:1, 0:7, mask:bits>>),
  )
}

pub fn it_should_parse_valid_request_test() {
  let req =
    "GET /index.html HTTP/1.1
Host: www.example.com
User-Agent: Mozilla/5.0
Accept: text/xml,application/xml,application/xhtml+xml,text/html*/*
Accept-Language: en-us
Accept-Charset: ISO-8859-1,utf-8
Connection: keep-alive

"

  let expected =
    request.new()
    |> request.set_body(Nil)
    |> request.set_path("/index.html")
    |> request.set_host("www.example.com")
    |> request.set_scheme(Http)
    |> request.set_header("connection", "keep-alive")
    |> request.set_header("accept-charset", "ISO-8859-1,utf-8")
    |> request.set_header("accept-language", "en-us")
    |> request.set_header(
      "accept",
      "text/xml,application/xml,application/xhtml+xml,text/html*/*",
    )
    |> request.set_header("user-agent", "Mozilla/5.0")
    |> request.set_header("host", "www.example.com")

  req
  |> bit_array.from_string
  |> gramps_http.read_request
  |> should.equal(Ok(#(expected, <<>>)))
}

pub fn it_should_parse_valid_response_test() {
  let resp =
    "HTTP/1.1 201 Created
Location: http://localhost/objectserver/restapi/alerts/status/kf/12481%3ANCOMS
Cache-Control: no-cache
Server: libnhttpd
Date: Wed Jul 4 15:31:53 2012
Connection: Keep-Alive
Content-Type: application/json;charset=UTF-8
Content-Length: 304

{
	\"entry\":	{
		\"affectedRows\": 1,
		\"keyField\": \"12481%3ANCOMS\",
		\"uri\": \"http://localhost/objectserver/restapi/alerts/status/kf/12481%3ANCOMS\"
	}
}"

  let expected =
    response.new(201)
    |> response.set_body(Nil)
    |> response.set_header("content-length", "304")
    |> response.set_header("content-type", "application/json;charset=UTF-8")
    |> response.set_header("connection", "Keep-Alive")
    |> response.set_header("date", "Wed Jul 4 15:31:53 2012")
    |> response.set_header("server", "libnhttpd")
    |> response.set_header("cache-control", "no-cache")
    |> response.set_header(
      "location",
      "http://localhost/objectserver/restapi/alerts/status/kf/12481%3ANCOMS",
    )

  gramps_http.read_response(bit_array.from_string(resp))
  |> should.equal(
    Ok(
      #(expected, <<
        "{
	\"entry\":	{
		\"affectedRows\": 1,
		\"keyField\": \"12481%3ANCOMS\",
		\"uri\": \"http://localhost/objectserver/restapi/alerts/status/kf/12481%3ANCOMS\"
	}
}":utf8,
      >>),
    ),
  )
}

pub fn it_should_return_literal_bits_simple_test() {
  let bits = <<1:1>>
  let literal = debug.literal_bits(bits, [])

  literal |> should.equal([1])
}

pub fn it_should_return_literal_bits_complex_test() {
  let bits = <<129, 7, 111, 112, 101, 110, 101, 100, 33>>
  let literal = debug.literal_bits(bits, [])

  literal
  |> should.equal([
    1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 1, 1, 0, 1, 1, 0, 1, 1, 1, 1, 0, 1,
    1, 1, 0, 0, 0, 0, 0, 1, 1, 0, 0, 1, 0, 1, 0, 1, 1, 0, 1, 1, 1, 0, 0, 1, 1, 0,
    0, 1, 0, 1, 0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1,
  ])
}
