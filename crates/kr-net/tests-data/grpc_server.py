import sys
from concurrent import futures
import grpc

def echo(req, ctx):
    return req

def stream(req, ctx):
    for i in range(3):
        yield req + bytes([i])

def err(req, ctx):
    ctx.abort(grpc.StatusCode.NOT_FOUND, "nope ü 100%")

h = grpc.method_handlers_generic_handler("t.Svc", {
    "Echo": grpc.unary_unary_rpc_method_handler(echo),
    "Stream": grpc.unary_stream_rpc_method_handler(stream),
    "Err": grpc.unary_unary_rpc_method_handler(err),
})
opts = [("grpc.max_send_message_length", -1), ("grpc.max_receive_message_length", -1)]
s = grpc.server(futures.ThreadPoolExecutor(4), options=opts)
s.add_generic_rpc_handlers((h,))
s.add_insecure_port("unix:" + sys.argv[1])
s.start()
s.wait_for_termination()
