Module:    httpi
Synopsis:  WebSocket support (RFC 6455)
Author:    Vadim Macagon
Copyright: See LICENSE file in this distribution.

// Any resource that is served over a websocket should inherit from <websocket-resource>.
define open class <websocket-resource> (<resource>)
  slot socket :: <tcp-socket>;
  // The protocol chosen by the server out of the protocols supported by the client,
  // or #f if none was chosen.
  slot protocol :: false-or(<byte-string>) = #f;
  // The extensions chosen by the server out of the extensions supported by the client,
  // or #f if none were chosen.
  slot extensions :: false-or(<byte-string>) = #f;
  // These frames will be sent to the client.
  constant slot outgoing-frames :: <deque> = make(<deque>);
end;

// The server should select a protocol and extensions out of those supported by the client.
define generic select-protocol-and-extensions
    (resource :: <websocket-resource>, client-protocols :: <object>, client-extensions :: <object>)
 => (successful? :: <boolean>);

// This will be called for every frame received from the client (before it's unmasked).
define generic process-incoming-frame
    (resource :: <websocket-resource>, frame :: <websocket-frame>) => ();

// Override this method in a <websocket-resource> subclass to handle protocol and extension
// negotiation
define method respond-to-get
    (resource :: <websocket-resource>, #key)
  let response = current-response();
  response.response-code := 101; // Switching Protocols
  set-header(response, "Upgrade", "websocket");
  set-header(response, "Connection", "Upgrade");
  let request = current-request();
  let accept-code = concatenate(get-header(request, "Sec-WebSocket-Key", parsed: #t),
                                "258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
  set-header(response, "Sec-WebSocket-Accept", sha1(accept-code));

  let client-protocols = get-header(request, "Sec-WebSocket-Protocol", parsed: #t);
  let client-extensions = get-header(request, "Sec-WebSocket-Extensions", parsed: #t);
  if (select-protocol-and-extensions(resource, client-protocols, client-extensions))
    if (resource.protocol)
      set-header(response, "Sec-WebSocket-Protocol", resource.protocol);
    end if;
    if (resource.extensions)
      set-header(response, "Sec-WebSocket-Extensions", resource.extensions);
    end if;
  end if;

  let socket = request.request-socket;
  resource.socket := socket;

  send-response-line(response, socket);
  send-headers(response, socket);

  // spawn a new thread to handle the WebSocket traffic from here on
  make(<thread>, function: curry(process-frames, resource));
end;

define method process-frames
    (server :: <websocket-resource>)
  // TODO: deal with errors, and close the connection and exit the loop at some point
  while (#t)
    let frame = parse-frame(<websocket-frame>, stream-contents(server.socket));
    process-incoming-frame(server, frame);
    write(server.socket, packet(assemble-frame(server.outgoing-frames.pop())));
  end;
end;

// Dylan does not currently support 64-bit integers, so this type is defined for use as a
// placeholder in the frame structure.
define n-byte-vector(<big-endian-unsigned-integer-8byte>, 8) end;

define binary-data <websocket-frame> (<header-frame>)
  field fin :: <boolean-bit> = #f;
  field rsv1 :: <boolean-bit> = #f;
  field rsv2 :: <boolean-bit> = #f;
  field rsv3 :: <boolean-bit> = #f;
  enum field opcode :: <4bit-unsigned-integer> = 0,
    mappings: { #x0 <=> #"continuation",
                #x1 <=> #"text",
                #x2 <=> #"binary",
                #x8 <=> #"close",
                #x9 <=> #"ping",
                #xA <=> #"pong" };
  field mask :: <boolean-bit> = #f;
  field payload-length :: <7bit-unsigned-integer> = 0;
  variably-typed field extended-payload-length, type-function:
    case
      frame.payload-length < 126 => <null-frame>;
      frame.payload-length = 126 => <2byte-big-endian-unsigned-integer>;
      frame.payload-length = 127 => <big-endian-unsigned-integer-8byte>; // 64-bit integer
    end;
  variably-typed field masking-key, type-function:
    if (frame.mask) <big-endian-unsigned-integer-4byte> else <null-frame> end;
  variably-typed field payload,
    start: compute-header-length(frame) * 8,
    length: compute-full-payload-length(frame) * 8;
end;

// Compute the header length (in bytes) of a WebSocket frame.
define method compute-header-length
    (frame :: <websocket-frame>)
  let mask-length = if (frame.mask) 4 else 0 end;
  case
    frame.payload-length < 126 => 2 + mask-length;
    frame.payload-length = 126 => 2 + 2 + mask-length;
    frame.payload-length = 127 => 2 + 8 + mask-length;
  end;
end;

// Compute the full payload length (in bytes) of a WebSocket frame.
define method compute-full-payload-length
    (frame :: <websocket-frame>)
  if (frame.payload-length < 126)
    frame.payload-length
  else
    frame.extended-payload-length.getter
  end if;
end;
