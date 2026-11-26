import importlib
import sys
import types


def load_handler(monkeypatch, pipeline, request_class):
    class FakeMangum:
        def __init__(self, app, lifespan):
            self.app = app
            self.lifespan = lifespan

        def __call__(self, event, context):
            return {"source": "asgi", "event": event}

    fake_main = types.SimpleNamespace(
        ScanRequest=request_class,
        app=object(),
        run_scan_pipeline=pipeline,
    )
    monkeypatch.setitem(sys.modules, "main", fake_main)
    monkeypatch.setitem(
        sys.modules, "mangum", types.SimpleNamespace(Mangum=FakeMangum)
    )
    module = importlib.import_module("lambda_handler")
    return importlib.reload(module)


def test_http_event_uses_fastapi_handler(monkeypatch):
    async def pipeline(scan_id, clerk_id, request):
        raise AssertionError("HTTP events must not run the scan pipeline")

    module = load_handler(monkeypatch, pipeline, object)
    event = {"requestContext": {"http": {"method": "GET", "path": "/"}}}

    assert module.handler(event, None) == {"source": "asgi", "event": event}


def test_scan_event_runs_pipeline_to_completion(monkeypatch):
    calls = []

    class FakeScanRequest:
        def __init__(self, **payload):
            self.payload = payload

    async def pipeline(scan_id, clerk_id, request):
        calls.append((scan_id, clerk_id, request.payload))

    module = load_handler(monkeypatch, pipeline, FakeScanRequest)
    event = {
        "authmap_job": "scan",
        "scan_id": "scan-123",
        "clerk_id": "user-456",
        "request": {"provider": "aws", "selected_compliances": ["SOC2"]},
    }

    assert module.handler(event, None) == {
        "status": "completed",
        "scan_id": "scan-123",
    }
    assert calls == [
        ("scan-123", "user-456", {"provider": "aws", "selected_compliances": ["SOC2"]})
    ]
