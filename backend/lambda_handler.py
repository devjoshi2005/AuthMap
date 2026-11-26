import asyncio

from mangum import Mangum

from main import ScanRequest, app, run_scan_pipeline


_asgi_handler = Mangum(app, lifespan="auto")


def handler(event, context):
    """Handle HTTP requests and asynchronous scan jobs."""
    if event.get("authmap_job") == "scan":
        request = ScanRequest(**event["request"])
        asyncio.run(run_scan_pipeline(event["scan_id"], event["clerk_id"], request))
        return {"status": "completed", "scan_id": event["scan_id"]}

    return _asgi_handler(event, context)
