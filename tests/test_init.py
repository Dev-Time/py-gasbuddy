"""Library tests."""

import json
import logging

import pytest
from aiohttp.client_exceptions import ServerTimeoutError

import gasbuddy
from tests.common import load_fixture

pytestmark = pytest.mark.asyncio

# GasBuddy URLs
GB_GRAPHQL_URL = "https://www.gasbuddy.com/graphql"
GB_HOME_URL = "https://www.gasbuddy.com/home"

# FlareSolverr settings
FLARESOLVERR_URL = "http://localhost:8191/v1"
FLARESOLVERR_SESSION_ID = "test-session-123"
FLARESOLVERR_USER_AGENT = "FlareSolverr-Test-UA/1.0"

# Sample Payloads / Responses
SAMPLE_QUERY = {"operationName": "TestQuery", "query": "query Test { test }", "variables": {}}
SAMPLE_JSON_QUERY = json.dumps(SAMPLE_QUERY)

# --- Helper to create FlareSolverr responses ---
def create_flaresolverr_response(
    status="ok",
    message="Challenge solved.",
    session_id=FLARESOLVERR_SESSION_ID,
    gb_response_data=None,
    gb_status_code=200,
    cookies=None,
    user_agent=FLARESOLVERR_USER_AGENT,
):
    """Helper to create FlareSolverr JSON responses."""
    if gb_response_data is None:
        gb_response_data = {"data": {"it": "worked"}}

    solution = {
        "url": GB_GRAPHQL_URL,
        "status": gb_status_code,
        "cookies": cookies or [],
        "userAgent": user_agent,
        "response": json.dumps(gb_response_data),
        "headers": {}, # Mocked GasBuddy response headers
    }
    if gb_status_code >= 400: # If GasBuddy itself returned an error
        solution["response"] = json.dumps({"errors": [{"message": "GasBuddy error via FS"}]})


    return {
        "status": status,
        "message": message,
        "session": session_id, # For session.create
        "solution": solution, # For request.post/get
        "startTimestamp": 1600000000000,
        "endTimestamp": 1600000001000,
        "version": "v2.0.0", # Example version
    }

# --- Tests ---

async def test_init_no_flaresolverr():
    """Test GasBuddy initialization without FlareSolverr."""
    gb = gasbuddy.GasBuddy()
    assert gb._flaresolverr_url is None
    assert gb._flaresolverr_session is None
    await gb.close() # Should be a no-op for FS parts

async def test_init_with_flaresolverr_url():
    """Test GasBuddy initialization with FlareSolverr URL."""
    gb = gasbuddy.GasBuddy(flaresolverr_url=FLARESOLVERR_URL)
    assert gb._flaresolverr_url == FLARESOLVERR_URL
    assert gb._flaresolverr_session is not None
    assert not gb._flaresolverr_session.closed
    await gb.close()
    assert gb._flaresolverr_session.closed


async def test_flaresolverr_session_creation_success(mock_aioclient, caplog):
    """Test successful FlareSolverr session creation."""
    mock_aioclient.post(
        FLARESOLVERR_URL,
        payload=create_flaresolverr_response(session_id=FLARESOLVERR_SESSION_ID),
        status=200,
    )
    gb = gasbuddy.GasBuddy(flaresolverr_url=FLARESOLVERR_URL)
    # Trigger session creation by attempting a request
    # Mock GasBuddy direct calls to ensure FlareSolverr path is intended
    mock_aioclient.get(GB_HOME_URL, status=404) # Should not be called if FS session create works
    mock_aioclient.post(GB_GRAPHQL_URL, status=404) # Should not be called

    # Mock the actual request.post to FS for the query itself
    mock_aioclient.post(
        FLARESOLVERR_URL, # This is the second call to FS for the actual query
        payload=create_flaresolverr_response(gb_response_data={"data": "success"}),
        status=200,
    )

    with caplog.at_level(logging.INFO):
        await gb.process_request(SAMPLE_QUERY)

    assert f"FlareSolverr session created successfully: {FLARESOLVERR_SESSION_ID}" in caplog.text
    assert gb._flaresolverr_session_id == FLARESOLVERR_SESSION_ID
    await gb.close()


async def test_flaresolverr_session_creation_failure(mock_aioclient, caplog):
    """Test failed FlareSolverr session creation."""
    mock_aioclient.post(
        FLARESOLVERR_URL, # For sessions.create
        payload={"status": "error", "message": "Failed to create session"},
        status=500,
    )
    gb = gasbuddy.GasBuddy(flaresolverr_url=FLARESOLVERR_URL)

    # Mock direct GasBuddy calls for fallback
    mock_aioclient.get(GB_HOME_URL, status=200, body=load_fixture("index.html"))
    mock_aioclient.post(GB_GRAPHQL_URL, status=200, body=json.dumps({"data": "direct_fallback_success"}))

    with caplog.at_level(logging.ERROR):
        response = await gb.process_request(SAMPLE_QUERY)

    assert "Failed to create FlareSolverr session." in caplog.text # General FS error
    assert gb._flaresolverr_session_id is None
    assert response == {"data": "direct_fallback_success"} # Check that it fell back
    await gb.close()


async def test_process_request_with_flaresolverr_success(mock_aioclient, caplog):
    """Test a successful request via FlareSolverr."""
    gbcsrf_token_value = "flaresolverr_csrf_token_123"
    flaresolverr_response = create_flaresolverr_response(
        gb_response_data={"data": {"key": "value"}},
        cookies=[{"name": "gbcsrf", "value": gbcsrf_token_value}],
        user_agent="TestUserAgentFS/1.0"
    )

    # Mock session.create
    mock_aioclient.post(
        FLARESOLVERR_URL,
        payload=create_flaresolverr_response(session_id=FLARESOLVERR_SESSION_ID, user_agent="TestUserAgentFS/1.0"),
        status=200,
        # Match the sessions.create payload specifically if your mock_aioclient supports it easily,
        # otherwise, ensure calls are ordered or distinct enough.
        # For simplicity, often the first post to FLARESOLVERR_URL is session.create
    )
    # Mock request.post for the actual query
    # This might require more specific matching if mock_aioclient is not call-order based
    # For now, assuming subsequent POST to same URL is the data request
    # A better mock would inspect the payload for "cmd": "request.post"

    # To ensure the calls are distinct for the mock, we can use a regex or a more specific URL if needed,
    # but pytest-aiohttp typically matches in order of definition for the same URL+method.
    # Let's assume the first POST is create, second is the actual request.

    mock_aioclient.post(FLARESOLVERR_URL, payload=flaresolverr_response, status=200)


    gb = gasbuddy.GasBuddy(flaresolverr_url=FLARESOLVERR_URL)
    with caplog.at_level(logging.DEBUG):
        data = await gb.process_request(SAMPLE_QUERY)

    assert data == {"data": {"key": "value"}}
    assert f"Updated gbcrsf token from FlareSolverr cookies: {gbcsrf_token_value}" in caplog.text
    assert gb._tag == gbcsrf_token_value
    assert gb._flaresolverr_user_agent == "TestUserAgentFS/1.0"

    # Verify FlareSolverr was called with correct cmd: request.post
    # This requires inspecting call history from mock_aioclient, which can be tricky.
    # Relying on logs and successful execution path.
    # For example, the log "FlareSolverr session created successfully" implies sessions.create was called.
    # And successful data return implies request.post was called.
    assert "sessions.create" in caplog.text # Check if the log indicates the call
    assert f"Processing request via FlareSolverr. URL: {FLARESOLVERR_URL}" in caplog.text
    assert SAMPLE_JSON_QUERY in caplog.text # Check if postData was logged

    await gb.close()


async def test_process_request_with_flaresolverr_gasbuddy_error(mock_aioclient, caplog):
    """Test FlareSolverr request where GasBuddy returns an error."""
    flaresolverr_response_with_gb_error = create_flaresolverr_response(
        gb_status_code=404, # GasBuddy returns 404
        gb_response_data={"errors": [{"message": "Not Found from GasBuddy"}]}
    )

    mock_aioclient.post(FLARESOLVERR_URL, payload=create_flaresolverr_response(), status=200) # session.create
    mock_aioclient.post(FLARESOLVERR_URL, payload=flaresolverr_response_with_gb_error, status=200) # request.post

    gb = gasbuddy.GasBuddy(flaresolverr_url=FLARESOLVERR_URL)
    with caplog.at_level(logging.DEBUG):
        data = await gb.process_request(SAMPLE_QUERY)

    assert "FlareSolverr indicated error status 404 for URL" in caplog.text
    assert "error" in data
    assert data["error"] == [{"message": "GasBuddy error via FS"}] # Corrected expected error structure
    await gb.close()


async def test_process_request_with_flaresolverr_api_error(mock_aioclient, caplog):
    """Test FlareSolverr request where FlareSolverr itself returns an error."""
    flaresolverr_api_error_response = {
        "status": "error",
        "message": "FlareSolverr internal error",
        "startTimestamp": 1600000000000,
        "endTimestamp": 1600000001000,
        "version": "v2.0.0",
    }

    mock_aioclient.post(FLARESOLVERR_URL, payload=create_flaresolverr_response(), status=200) # session.create
    mock_aioclient.post(FLARESOLVERR_URL, payload=flaresolverr_api_error_response, status=500) # request.post fails

    gb = gasbuddy.GasBuddy(flaresolverr_url=FLARESOLVERR_URL)
    with caplog.at_level(logging.ERROR):
        data = await gb.process_request(SAMPLE_QUERY)

    assert "FlareSolverr request failed." in caplog.text
    assert "error" in data
    assert data["error"] == "FlareSolverr error: FlareSolverr internal error"
    await gb.close()

async def test_process_request_fallback_if_flaresolverr_session_fails_then_direct(mock_aioclient, caplog):
    """Test fallback to direct if FlareSolverr session.create fails."""
    # Mock FlareSolverr session.create to fail
    mock_aioclient.post(
        FLARESOLVERR_URL,
        payload={"status": "error", "message": "FS session create failed"},
        status=500,
    )

    # Mock direct GasBuddy calls (these should be hit)
    direct_gb_response = {"data": {"source": "direct_gasbuddy"}}
    mock_aioclient.get(GB_HOME_URL, status=200, body=load_fixture("index.html")) # For _get_headers
    mock_aioclient.post(GB_GRAPHQL_URL, status=200, payload=direct_gb_response) # For actual query

    gb = gasbuddy.GasBuddy(flaresolverr_url=FLARESOLVERR_URL)
    with caplog.at_level(logging.DEBUG):
        data = await gb.process_request(SAMPLE_QUERY)

    assert "Failed to create FlareSolverr session" in caplog.text
    assert "Processing request directly to GasBuddy" in caplog.text
    assert data == direct_gb_response
    # Check that gbcrsf was NOT obtained by direct call due to FS config, and a warning was logged
    assert "CSRF token found directly: 1.+Qw4hH/vdM0Kvscg" not in caplog.text
    assert "Proceeding with direct request without CSRF token" in caplog.text
    await gb.close()


async def test_close_flaresolverr_session(mock_aioclient, caplog):
    """Test closing of FlareSolverr session."""
    # Mock session.create
    mock_aioclient.post(FLARESOLVERR_URL, payload=create_flaresolverr_response(session_id="closable_session"), status=200)
    # Mock request.post (to trigger session ID storage)
    mock_aioclient.post(FLARESOLVERR_URL, payload=create_flaresolverr_response(gb_response_data={"data":"closing test"}), status=200)
    # Mock session.destroy
    destroy_response = {"status": "ok", "message": "Session destroyed"}
    mock_aioclient.post(FLARESOLVERR_URL, payload=destroy_response, status=200)

    gb = gasbuddy.GasBuddy(flaresolverr_url=FLARESOLVERR_URL)
    await gb.process_request(SAMPLE_QUERY) # Ensure session is created and ID stored
    assert gb._flaresolverr_session_id == "closable_session"

    with caplog.at_level(logging.DEBUG): # Changed to DEBUG
        await gb.close()

    assert "FlareSolverr session closable_session destroyed successfully." in caplog.text

    # Check that session.destroy was actually called by checking logs
    assert "Closing FlareSolverr session: closable_session" in caplog.text
    assert "FlareSolverr session closable_session destroyed successfully." in caplog.text
    assert gb._flaresolverr_session.closed


# --- Existing tests (ensure they are not broken by aliasing URLs) ---

async def test_location_search(mock_aioclient, caplog):
    """Test location_search function."""
    mock_aioclient.get(
        GB_HOME_URL,  # Corrected
        status=200,
        body=load_fixture("index.html"),
        repeat=True,
    )
    mock_aioclient.post(
        GB_GRAPHQL_URL,  # Corrected
        status=200,
        body=load_fixture("location.json"),
    )
    with caplog.at_level(logging.DEBUG):
        data = await gasbuddy.GasBuddy().location_search(zipcode=12345)

    assert (
        data["data"]["locationBySearchTerm"]["stations"]["results"][0]["id"] == "187725"
    )
    assert "CSRF token found directly: 1.+Qw4hH/vdM0Kvscg" in caplog.text # Corrected log message


async def test_location_search_timeout(mock_aioclient, caplog):
    """Test server timeout exception handling."""
    mock_aioclient.get(
        GB_HOME_URL,  # Corrected
        status=200,
        body=load_fixture("index.html"),
        repeat=True,
    )
    mock_aioclient.post(
        GB_GRAPHQL_URL,  # Corrected
        exception=ServerTimeoutError,
    )
    with caplog.at_level(logging.DEBUG):
        await gasbuddy.GasBuddy().location_search(zipcode=12345)
    assert gasbuddy.ERROR_TIMEOUT in caplog.text


async def test_location_search_exception(mock_aioclient):
    """Test location_search function."""
    mock_aioclient.post(
        GB_GRAPHQL_URL,  # Corrected
        status=200,
        body=load_fixture("location.json"),
    )
    with pytest.raises(gasbuddy.MissingSearchData):
        await gasbuddy.GasBuddy().location_search()


async def test_price_lookup(mock_aioclient):
    """Test price_lookup function."""
    mock_aioclient.get(
        GB_HOME_URL,  # Corrected
        status=200,
        body=load_fixture("index.html"),
        repeat=True,
    )
    mock_aioclient.post(
        GB_GRAPHQL_URL,  # Corrected
        status=200,
        body=load_fixture("station.json"),
    )
    data = await gasbuddy.GasBuddy(station_id=205033).price_lookup()

    assert data["station_id"] == "205033"
    assert data["regular_gas"]["price"] == 3.27
    assert data["regular_gas"]["cash_price"] == 3.17
    assert data["regular_gas"]["credit"] == "Flemmit"
    assert data["regular_gas"]["last_updated"] == "2024-09-06T09:54:05.489Z"
    assert data["unit_of_measure"] == "dollars_per_gallon"
    assert data["currency"] == "USD"
    assert not data["image_url"]
    assert not data["premium_gas"]["price"]
    assert not data["premium_gas"]["cash_price"]

    mock_aioclient.post(
        GB_GRAPHQL_URL,  # Corrected
        status=200,
        body=load_fixture("station2.json"),
    )
    data = await gasbuddy.GasBuddy(station_id=197274).price_lookup()

    assert data["station_id"] == "197274"
    assert data["regular_gas"]["price"] == 131.9
    assert not "cash_price" in data["regular_gas"]
    assert data["regular_gas"]["credit"] == "qjnw4hgzcn"
    assert data["regular_gas"]["last_updated"] == "2024-09-06T14:42:39.298Z"
    assert data["unit_of_measure"] == "cents_per_liter"
    assert data["currency"] == "CAD"
    assert data["latitude"] == 53.3066
    assert data["longitude"] == -113.5559
    assert data["image_url"] == "https://images.gasbuddy.io/b/117.png"


async def test_price_lookup_service(mock_aioclient, caplog):
    """Test price_lookup function."""
    mock_aioclient.get(
        GB_HOME_URL,  # Corrected
        status=200,
        body=load_fixture("index.html"),
        repeat=True,
    )
    mock_aioclient.post(
        GB_GRAPHQL_URL,  # Corrected
        status=200,
        body=load_fixture("prices_gps.json"),
    )
    with caplog.at_level(logging.DEBUG):
        data = await gasbuddy.GasBuddy().price_lookup_service(lat=1234, lon=5678)

    assert isinstance(data, dict)
    assert data["results"][0] == {
        "station_id": "187725",
        "unit_of_measure": "dollars_per_gallon",
        "currency": "USD",
        "latitude": 33.465405037595,
        "longitude": -112.505053281784,
        "regular_gas": {
            "credit": "fred1129",
            "price": 3.28,
            "last_updated": "2024-11-18T21:58:38.859Z",
        },
        "midgrade_gas": {
            "credit": "fred1129",
            "price": 3.73,
            "last_updated": "2024-11-18T21:58:38.891Z",
        },
        "premium_gas": {
            "credit": "fred1129",
            "price": 4,
            "last_updated": "2024-11-18T21:58:38.915Z",
        },
        "diesel": {
            "credit": "fred1129",
            "price": 3.5,
            "last_updated": "2024-11-18T21:58:38.946Z",
        },
    }
    assert len(data["results"]) == 5
    assert data["trend"] == {
        "average_price": 3.33,
        "lowest_price": 2.59,
        "area": "Arizona",
    }
    assert len(data["trend"]) == 3

    mock_aioclient.post(
        GB_GRAPHQL_URL,  # Corrected
        status=200,
        body=load_fixture("prices_gps.json"),
    )
    with caplog.at_level(logging.DEBUG):
        data = await gasbuddy.GasBuddy().price_lookup_service(zipcode=12345)

    assert isinstance(data, dict)
    assert data["results"][0] == {
        "station_id": "187725",
        "unit_of_measure": "dollars_per_gallon",
        "currency": "USD",
        "latitude": 33.465405037595,
        "longitude": -112.505053281784,
        "regular_gas": {
            "credit": "fred1129",
            "price": 3.28,
            "last_updated": "2024-11-18T21:58:38.859Z",
        },
        "midgrade_gas": {
            "credit": "fred1129",
            "price": 3.73,
            "last_updated": "2024-11-18T21:58:38.891Z",
        },
        "premium_gas": {
            "credit": "fred1129",
            "price": 4,
            "last_updated": "2024-11-18T21:58:38.915Z",
        },
        "diesel": {
            "credit": "fred1129",
            "price": 3.5,
            "last_updated": "2024-11-18T21:58:38.946Z",
        },
    }
    assert len(data["results"]) == 5
    assert data["trend"] == {
        "average_price": 3.33,
        "lowest_price": 2.59,
        "area": "Arizona",
    }
    assert len(data["trend"]) == 3

    mock_aioclient.post(
        GB_GRAPHQL_URL,  # Corrected
        status=200,
        body="[...]",
    )
    with pytest.raises(gasbuddy.exceptions.LibraryError):
        data = await gasbuddy.GasBuddy().price_lookup_service(lat=1234, lon=5678)

    mock_aioclient.post(
        GB_GRAPHQL_URL,  # Corrected
        status=200,
        body=json.dumps({"errors": {"message": "Fake Error"}}),
    )
    with pytest.raises(gasbuddy.exceptions.APIError):
        data = await gasbuddy.GasBuddy().price_lookup_service(lat=1234, lon=5678)


async def test_header_errors(mock_aioclient, caplog):
    """Test price_lookup function."""
    mock_aioclient.get(GB_HOME_URL, status=404, body="Not Found") # Corrected
    mock_aioclient.post(
        GB_GRAPHQL_URL,  # Corrected
        status=200,
        body=load_fixture("station.json"),
        repeat=True,
    )
    await gasbuddy.GasBuddy(station_id=205033).price_lookup()
    assert (
        "Error retrieving CSRF page, status: 404\nmessage: Not Found"  # Updated expected log
        in caplog.text
    )
    mock_aioclient.get(
        GB_HOME_URL,  # Corrected
        status=404, # Should be an exception for timeout test part
        exception=ServerTimeoutError,
    )
    with caplog.at_level(logging.DEBUG):
        # This call will try to get headers, fail with timeout, then proceed to POST.
        # The POST will also need a mock if we expect it to be called.
        # For this test, we are focused on the _get_headers failure.
        # If _get_headers fails and self._tag is empty, process_request will try to post without gbcrsf.
        # Let's ensure the POST for station data is also mocked to avoid unexpected errors.
        mock_aioclient.post(GB_GRAPHQL_URL, status=200, body=load_fixture("station.json"), repeat=True)
        await gasbuddy.GasBuddy(station_id=205033).price_lookup()
    assert (
        "Timeout wile getting CSRF tokens: https://www.gasbuddy.com/home while fetching CSRF token. Error: " in caplog.text # Fully corrected
    )
    mock_aioclient.get(
        GB_HOME_URL,  # Corrected
        status=200,
        body="<html></html>",
    )
    with caplog.at_level(logging.DEBUG):
            # CSRFTokenMissing is no longer raised from _get_headers directly.
            # The library will attempt the request, possibly without the token.
            await gasbuddy.GasBuddy(station_id=205033).price_lookup()
    assert "CSRF token not found in direct response from /home." in caplog.text
    assert "Proceeding with direct request without CSRF token after _get_headers." in caplog.text


async def test_retry_logic(mock_aioclient, caplog):
    """Test retry logic."""
    mock_aioclient.get(
        GB_HOME_URL,  # Corrected
        status=200,
        body=load_fixture("index.html"),
        repeat=True,
    )
    mock_aioclient.post(
        GB_GRAPHQL_URL,  # Corrected
        status=403,
        body='<!DOCTYPE html><html lang="en-US"><head><title>Just a moment...</title></html>',
        repeat=True,
    )
    with caplog.at_level(logging.DEBUG):
        with pytest.raises(gasbuddy.LibraryError):
            await gasbuddy.GasBuddy(station_id=205033).price_lookup()
    assert "Direct request got 403, retrying" in caplog.text # Corrected log message
