"""Development-only mitmdump addon for synthetic controlled fixture URLs only."""
import json
import os


def request(flow):
    record = {"method": flow.request.method, "host": flow.request.host,
              "path": flow.request.path}
    with open(os.environ["OUTBOUND_GUARD_PROXY_FLOW_LOG"], "a", encoding="utf-8") as output:
        output.write(json.dumps(record, separators=(",", ":")) + "\n")
