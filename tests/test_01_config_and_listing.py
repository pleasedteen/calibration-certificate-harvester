"""Configuration, readiness, listing and paging behaviour."""

from __future__ import annotations

from .conftest import wait_ready, wait_until


def test_orgs_can_be_configured_via_http(client, runtime):
    status, body = client.post(
        "/api/orgs",
        {
            "org_id": "lab-a",
            "name": "Laboratory A",
            "source": {"kind": "html", "base_url": "http://sim.local"},
            "limits": {"max_concurrency": 1, "min_interval_ms": 5},
            "options": {"poll_interval_ms": 100},
        },
    )
    assert status == 201, body
    assert body["org_id"] == "lab-a"
    assert body["source"]["kind"] == "html"
    assert body["limits"]["max_concurrency"] == 1

    status, body = client.post(
        "/api/orgs",
        {"org_id": "lab-b", "source": {"kind": "json", "base_url": "http://sim.local/json"}},
    )
    assert status == 201
    status, listing = client.get("/api/orgs")
    assert status == 200
    assert {o["org_id"] for o in listing["items"]} == {"lab-a", "lab-b"}


def test_not_ready_before_first_catalog(client, runtime):
    status, body = client.post(
        "/api/orgs",
        {
            "org_id": "slow-lab",
            "source": {"kind": "html", "base_url": "http://sim.local"},
            "options": {"poll_interval_ms": 100},
            "start": False,
        },
    )
    assert status == 201
    status, state = client.get("/api/orgs/slow-lab/status")
    assert status == 200
    assert state["ready"] is False
    assert state["phase"] in ("initializing", "idle")

    status, _ = client.get("/api/orgs/slow-lab/certs")
    assert status == 200

    status, err = client.post("/api/orgs/slow-lab/collect", {"mode": "incremental"})
    assert status == 202
    run_id = err["run_id"]
    wait_until(
        lambda: client.get(f"/api/orgs/slow-lab/runs/{run_id}")[1]["status"] == "failed",
        message="incremental before initial catalog fails",
    )
    assert client.get(f"/api/orgs/slow-lab/runs/{run_id}")[1]["error"]["code"] == "catalog_not_ready"


def test_html_and_json_sites_converge_to_source(client, runtime, sim):
    for org_id, kind, world in (
        ("site-html", "html", sim.html_world),
        ("site-json", "json", sim.json_world),
    ):
        client.post(
            "/api/orgs",
            {
                "org_id": org_id,
                "source": {
                    "kind": kind,
                    "base_url": "http://sim.local" if kind == "html" else "http://sim.local/json",
                },
                "options": {"poll_interval_ms": 100},
            },
        )
        wait_ready(runtime, org_id, count=len(world.state()["certs"]))
        status, page = client.get(f"/api/orgs/{org_id}/certs?page=1&page_size=5")
        assert status == 200
        assert page["total"] == len(world.state()["certs"])
        assert len(page["items"]) == 5
        assert page["pages"] == 3
        status, second = client.get(f"/api/orgs/{org_id}/certs?page=2&page_size=5")
        assert {c["cert_no"] for c in second["items"]}.isdisjoint(
            {c["cert_no"] for c in page["items"]}
        )
        status, detail = client.get(f"/api/orgs/{org_id}/certs/C-1001")
        assert status == 200
        assert detail["data"]["model"].startswith(kind.upper())
        status, missing = client.get(f"/api/orgs/{org_id}/certs/C-9999")
        assert status == 404


def test_status_reports_progress_and_caught_up(client, runtime, sim):
    client.post(
        "/api/orgs",
        {
            "org_id": "status-lab",
            "source": {"kind": "json", "base_url": "http://sim.local/json"},
            "options": {"poll_interval_ms": 100},
        },
    )
    wait_ready(runtime, "status-lab")
    status, body = client.get("/api/orgs/status-lab/status")
    assert status == 200
    assert body["catalog"]["caught_up"] is True
    assert body["phase"] in ("ready", "collecting", "scheduled")
    assert body["catalog"]["version"] >= 1
    assert body["catalog"]["cert_count"] == len(sim.json_world.state()["certs"])
    assert "upstream" in body
    assert body["upstream"]["stats"]["requests"] > 0


def test_invalid_configuration_is_rejected(client):
    status, body = client.post("/api/orgs", {"org_id": "bad/org"})
    assert status == 400
    assert body["error"] == "validation_error"
    status, body = client.post(
        "/api/orgs",
        {"org_id": "bad", "source": {"kind": "soap", "base_url": "http://x"}},
    )
    assert status == 400
    status, body = client.post(
        "/api/orgs",
        {"org_id": "bad", "limits": {"max_concurrency": 0}},
    )
    assert status == 400


def test_pagination_validation(client, runtime):
    client.post(
        "/api/orgs",
        {
            "org_id": "page-lab",
            "source": {"kind": "html", "base_url": "http://sim.local"},
            "options": {"poll_interval_ms": 100},
        },
    )
    wait_ready(runtime, "page-lab")
    status, body = client.get("/api/orgs/page-lab/certs?page=999&page_size=10")
    assert status == 200
    assert body["items"] == []
    status, body = client.get("/api/orgs/page-lab/certs?page=0")
    assert status == 400
    status, body = client.get("/api/orgs/page-lab/certs?page_size=100000")
    assert status == 200
    assert body["page_size"] == 500
