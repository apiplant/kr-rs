import sys
import grpc

ch = grpc.insecure_channel("unix:" + sys.argv[1], options=[
    ("grpc.max_send_message_length", -1), ("grpc.max_receive_message_length", -1)])
grpc.channel_ready_future(ch).result(timeout=10)
ident = dict(request_serializer=None, response_deserializer=None)
echo = ch.unary_unary("/t.Svc/Echo", **ident)
assert echo(b"hello", timeout=10) == b"hello"
big = bytes(range(256)) * (3 << 12)
assert echo(big, timeout=20) == big
msgs = list(ch.unary_stream("/t.Svc/Many", **ident)(b"", timeout=20))
assert len(msgs) == 1000 and msgs[999] == (999).to_bytes(4, "big"), len(msgs)
try:
    ch.unary_unary("/t.Svc/Err", **ident)(b"", timeout=10)
    assert False
except grpc.RpcError as e:
    assert e.code() == grpc.StatusCode.NOT_FOUND, e.code()
    assert e.details() == "not found: ü 100%\n", repr(e.details())
try:
    ch.unary_unary("/t.Svc/Nope", **ident)(b"", timeout=10)
    assert False
except grpc.RpcError as e:
    assert e.code() == grpc.StatusCode.UNIMPLEMENTED, e.code()
try:
    ch.unary_unary("/t.Svc/Hang", **ident)(b"", timeout=0.3)
    assert False
except grpc.RpcError as e:
    assert e.code() == grpc.StatusCode.DEADLINE_EXCEEDED, e.code()
print("CLIENT-OK")
