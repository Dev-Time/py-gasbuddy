"""Main functions for py-gasbuddy."""

from __future__ import annotations

import json
import logging
import re
from typing import Any, Collection

import aiohttp  # type: ignore
from aiohttp.client_exceptions import ContentTypeError, ServerTimeoutError
import backoff

from .consts import (
    BASE_URL,
    DEFAULT_HEADERS,
    GAS_PRICE_QUERY,
    LOCATION_QUERY,
    LOCATION_QUERY_PRICES,
)
from .exceptions import APIError, CSRFTokenMissing, LibraryError, MissingSearchData

ERROR_TIMEOUT = "Timeout while updating"
CSRF_TIMEOUT = "Timeout wile getting CSRF tokens"
MAX_RETRIES = 5
_LOGGER = logging.getLogger(__name__)


class GasBuddy:
    """Represent GasBuddy GraphQL calls."""

    def __init__(
        self,
        station_id: int | None = None,
        flaresolverr_url: str | None = None,
    ) -> None:
        """Connect and request data from GasBuddy."""
        self._url = BASE_URL
        self._id = station_id
        self._tag = ""
        self._flaresolverr_url = flaresolverr_url
        self._flaresolverr_session_id: str | None = None
        self._flaresolverr_session: aiohttp.ClientSession | None = None
        self._flaresolverr_user_agent: str | None = None

        if self._flaresolverr_url:
            self._flaresolverr_session = aiohttp.ClientSession()

    async def _create_flaresolverr_session(self) -> None:
        """Create a new FlareSolverr session."""
        if not self._flaresolverr_url or not self._flaresolverr_session:
            # This should not happen if called correctly
            _LOGGER.error("FlareSolverr URL or session not initialized.")
            return

        payload = {"cmd": "sessions.create"}
        _LOGGER.debug(
            "Creating FlareSolverr session with URL: %s, Payload: %s",
            self._flaresolverr_url,
            payload,
        )
        try:
            async with self._flaresolverr_session.post(
                self._flaresolverr_url,
                json=payload,
                timeout=aiohttp.ClientTimeout(total=60),
            ) as response:
                response_data = await response.json()
                _LOGGER.debug("FlareSolverr session.create response: %s", response_data)
                if response.status == 200 and response_data.get("status") == "ok":
                    self._flaresolverr_session_id = response_data.get("session")
                    # Attempt to get userAgent from the response, though it's not explicitly documented for sessions.create
                    # It's typically in request.get/post responses. We'll primarily rely on userAgent from the first actual request.
                    if "solution" in response_data and "userAgent" in response_data["solution"]:
                         self._flaresolverr_user_agent = response_data["solution"]["userAgent"]
                    _LOGGER.info(
                        "FlareSolverr session created successfully: %s",
                        self._flaresolverr_session_id,
                    )
                else:
                    _LOGGER.error(
                        "Failed to create FlareSolverr session. Status: %s, Response: %s",
                        response.status,
                        response_data,
                    )
                    # Potentially raise an exception here or handle error appropriately
        except aiohttp.ClientError as e:
            _LOGGER.error("Error creating FlareSolverr session: %s", e)
            # Potentially raise an exception
        except json.JSONDecodeError as e:
            _LOGGER.error("Error decoding FlareSolverr session.create response: %s", e)


    @backoff.on_exception(
        backoff.expo, aiohttp.ClientError, max_time=60, max_tries=MAX_RETRIES
    )
    async def process_request(
        self, query: dict[str, Collection[str]]
    ) -> dict[str, Any]:
        """Process API requests."""
        json_query: str = json.dumps(query)

        if self._flaresolverr_url and self._flaresolverr_session:
            if not self._flaresolverr_session_id:
                await self._create_flaresolverr_session()
                if not self._flaresolverr_session_id:
                    _LOGGER.error(
                        "Failed to create FlareSolverr session, falling back to direct request if possible or failing."
                    )
                    # Or raise an exception: raise APIError("Failed to initialize FlareSolverr session")
                    # For now, let's allow fallback if _get_headers can work, though it's unlikely if Cloudflare is the issue.

            if self._flaresolverr_session_id: # Proceed if session ID was obtained
                payload = {
                    "cmd": "request.post",
                    "url": self._url,
                    "postData": json_query,
                    "session": self._flaresolverr_session_id,
                    "maxTimeout": 60000,
                }
                # Add User-Agent to FlareSolverr request if we have it
                if self._flaresolverr_user_agent:
                    payload["userAgent"] = self._flaresolverr_user_agent

                _LOGGER.debug(
                    "Processing request via FlareSolverr. URL: %s, Payload: %s",
                    self._flaresolverr_url,
                    payload,
                )
                try:
                    async with self._flaresolverr_session.post(
                        self._flaresolverr_url,
                        json=payload,
                        headers={"Content-Type": "application/json"},
                        timeout=aiohttp.ClientTimeout(total=70), # Slightly more than maxTimeout for FlareSolverr
                    ) as response:
                        response_data = await response.json()
                        _LOGGER.debug("FlareSolverr response: %s", response_data)

                        if response.status == 200 and response_data.get("status") == "ok":
                            solution = response_data.get("solution", {})
                            # Store User-Agent from FlareSolverr for future requests
                            if "userAgent" in solution:
                                self._flaresolverr_user_agent = solution["userAgent"]

                            # Extract CSRF token from cookies
                            # FlareSolverr cookies are in solution.cookies
                            # Example: {"name": "gbcsrf", "value": "token_val"}
                            if "cookies" in solution:
                                for cookie in solution["cookies"]:
                                    if cookie.get("name") == "gbcsrf":
                                        self._tag = cookie["value"]
                                        _LOGGER.debug("Updated gbcrsf token from FlareSolverr cookies: %s", self._tag)
                                        break
                            # Response headers from GasBuddy are in solution["headers"].
                            # The gbcrsf token for the *request* is expected to be handled by FlareSolverr's cookie management within the session.
                            # We update self._tag from the cookies FlareSolverr reports back, which reflects the state after its request.

                            # The actual response from GasBuddy is in solution.response
                            gasbuddy_response_text = solution.get("response")
                            if gasbuddy_response_text:
                                try:
                                    message = json.loads(gasbuddy_response_text)
                                    # GasBuddy might return 200 but with internal errors
                                    if solution.get("status", 200) >= 400 : # Check FlareSolverr's view of the status
                                         _LOGGER.error(
                                            "FlareSolverr indicated error status %s for URL %s. Response: %s",
                                            solution.get("status"), self._url, gasbuddy_response_text
                                        )
                                         message = {"error": message.get("errors", "Unknown error from GasBuddy via FlareSolverr")}

                                    return message
                                except json.JSONDecodeError:
                                    _LOGGER.warning(
                                        "Non-JSON response from GasBuddy via FlareSolverr: %s",
                                        gasbuddy_response_text,
                                    )
                                    return {"error": gasbuddy_response_text}
                            else:
                                _LOGGER.error("No response content in FlareSolverr solution.")
                                return {"error": "No response content from FlareSolverr"}
                        else:
                            _LOGGER.error(
                                "FlareSolverr request failed. Status: %s, Response: %s",
                                response.status,
                                response_data,
                            )
                            return {"error": f"FlareSolverr error: {response_data.get('message', 'Unknown error')}"}
                except aiohttp.ClientError as e:
                    _LOGGER.error("Error during FlareSolverr request: %s", e)
                    return {"error": f"FlareSolverr communication error: {e}"}
                except json.JSONDecodeError as e:
                    _LOGGER.error("Error decoding FlareSolverr response: %s", e)
                    return {"error": f"FlareSolverr JSON decode error: {e}"}

        # Fallback to direct request if FlareSolverr is not configured or failed to initialize session
        _LOGGER.debug("Processing request directly to GasBuddy.")
        headers = DEFAULT_HEADERS.copy() # Use a copy to modify
        await self._get_headers() # This will attempt to get CSRF if not using FlareSolverr or if FS failed early

        # If FlareSolverr provided a user agent, use it. Otherwise, use the default.
        if self._flaresolverr_user_agent:
            headers["User-Agent"] = self._flaresolverr_user_agent

        if self._tag: # Ensure CSRF token is set if available
             headers["gbcsrf"] = self._tag
        else:
            _LOGGER.warning("Proceeding with direct request without CSRF token after _get_headers.")


        # Standard direct request logic
        async with aiohttp.ClientSession(headers=headers) as session:
            _LOGGER.debug("URL: %s\nQuery: %s", self._url, json_query)
            try:
                async with session.post(self._url, data=json_query, timeout=aiohttp.ClientTimeout(total=60)) as response:
                    message_text: str = ""
                    try:
                        message_text = await response.text()
                    except UnicodeDecodeError:
                        _LOGGER.debug("Decoding error on direct request.")
                        data = await response.read()
                        message_text = data.decode(errors="replace")

                    message: dict[str, Any]
                    try:
                        message = json.loads(message_text)
                    except json.JSONDecodeError: # Changed from ValueError for specificity
                        _LOGGER.warning("Non-JSON response (direct): %s", message_text)
                        message = {"error": message_text}

                    if response.status == 403:
                        _LOGGER.debug("Direct request got 403, retrying (if backoff is configured for this at a higher level).")
                        # Potentially update self._tag here if a new CSRF token is provided in this 403 response, though unlikely.
                    elif response.status != 200:
                        _LOGGER.error(
                            "Error retrieving data directly, code: %s\nmessage: %s",
                            response.status,
                            message,
                        )
                        # Ensure error is propagated
                        if "error" not in message:
                             message = {"error": message.get("errors", f"Direct request failed with status {response.status}")}
                    return message

            except (TimeoutError, ServerTimeoutError): # Standard Python TimeoutError
                _LOGGER.error("%s: %s", ERROR_TIMEOUT, self._url)
                message = {"error": ERROR_TIMEOUT}
            except aiohttp.ClientError as e: # Catch other aiohttp client errors
                _LOGGER.error("AIOHttp ClientError on direct request: %s", e)
                message = {"error": str(e)}

            # No explicit session.close() needed here due to async with
            return message

    async def location_search(
        self,
        lat: float | None = None,
        lon: float | None = None,
        zipcode: int | None = None,
    ) -> dict[str, str] | dict[str, Any]:
        """Return result of location search."""
        variables: dict[str, Any] = {}
        if lat is not None and lon is not None:
            variables = {"maxAge": 0, "lat": lat, "lng": lon}
        elif zipcode is not None:
            variables = {"maxAge": 0, "search": str(zipcode)}
        else:
            _LOGGER.error("Missing search data.")
            raise MissingSearchData

        query = {
            "operationName": "LocationBySearchTerm",
            "query": LOCATION_QUERY,
            "variables": variables,
        }

        return await self.process_request(query)

    async def price_lookup(self) -> dict[str, Any] | None:
        """Return gas price of station_id."""
        query = {
            "operationName": "GetStation",
            "query": GAS_PRICE_QUERY,
            "variables": {"id": str(self._id)},
        }

        # Parse and format data into easy to use dict
        response = await self.process_request(query)

        _LOGGER.debug("price_lookup response: %s", response)

        if "error" in response.keys():
            message = response["error"]
            _LOGGER.error(
                "An error occured attempting to retrieve the data: %s",
                message,
            )
            raise LibraryError
        if "errors" in response.keys():
            message = response["errors"]["message"]
            _LOGGER.error(
                "An error occured attempting to retrieve the data: %s",
                message,
            )
            raise APIError

        data = {}

        data["station_id"] = response["data"]["station"]["id"]
        data["unit_of_measure"] = response["data"]["station"]["priceUnit"]
        data["currency"] = response["data"]["station"]["currency"]
        data["latitude"] = response["data"]["station"]["latitude"]
        data["longitude"] = response["data"]["station"]["longitude"]
        data["image_url"] = None

        if len(response["data"]["station"]["brands"]) > 0:
            data["image_url"] = response["data"]["station"]["brands"][0]["imageUrl"]

        _LOGGER.debug("pre-price data: %s", data)

        prices = response["data"]["station"]["prices"]
        for price in prices:
            index = price["fuelProduct"]
            if price["cash"]:
                data[index] = {
                    "credit": price["credit"]["nickname"],
                    "cash_price": (
                        None
                        if price.get("cash", {}).get("price", 0) == 0
                        else price["cash"]["price"]
                    ),
                    "price": (
                        None
                        if price.get("credit", {}).get("price", 0) == 0
                        else price["credit"]["price"]
                    ),
                    "last_updated": price["credit"]["postedTime"],
                }
            else:
                data[index] = {
                    "credit": price["credit"]["nickname"],
                    "price": (
                        None
                        if price.get("credit", {}).get("price", 0) == 0
                        else price["credit"]["price"]
                    ),
                    "last_updated": price["credit"]["postedTime"],
                }

        _LOGGER.debug("final data: %s", data)

        return data

    async def price_lookup_service(
        self,
        lat: float | None = None,
        lon: float | None = None,
        zipcode: int | None = None,
        limit: int = 5,
    ) -> dict[str, Any] | None:
        """Return gas price of station_id."""
        variables: dict[str, Any] = {}
        if lat is not None and lon is not None:
            variables = {"maxAge": 0, "lat": lat, "lng": lon}
        elif zipcode is not None:
            variables = {"maxAge": 0, "search": str(zipcode)}
        query = {
            "operationName": "LocationBySearchTerm",
            "query": LOCATION_QUERY_PRICES,
            "variables": variables,
        }

        # Parse and format data into easy to use dict
        response = await self.process_request(query)

        _LOGGER.debug("price_lookup_service response: %s", response)

        if "error" in response.keys():
            message = response["error"]
            _LOGGER.error(
                "An error occured attempting to retrieve the data: %s",
                message,
            )
            raise LibraryError
        if "errors" in response.keys():
            message = response["errors"]["message"]
            _LOGGER.error(
                "An error occured attempting to retrieve the data: %s",
                message,
            )
            raise APIError

        result_list = await self._parse_results(response, limit)
        _LOGGER.debug("result data: %s", result_list)
        value: dict[Any, Any] = {}
        value["results"] = result_list
        trend_data = await self._parse_trends(response)
        if trend_data:
            value["trend"] = trend_data
            _LOGGER.debug("trend data: %s", trend_data)
        return value

    async def _parse_trends(self, response: dict) -> dict | None:
        """Parse API results and return trend dict."""
        trend_data: dict[str, Any] = {}
        if response["data"]["locationBySearchTerm"]["trends"][0]:
            result = response["data"]["locationBySearchTerm"]["trends"][0]
            trend_data["average_price"] = result["today"]
            trend_data["lowest_price"] = result["todayLow"]
            trend_data["area"] = result["areaName"]
        return trend_data

    async def _parse_results(self, response: dict, limit: int) -> list:
        """Parse API results and return price data list."""
        result_list = []
        for result in response["data"]["locationBySearchTerm"]["stations"]["results"]:
            if limit <= 0:
                break
            limit -= 1
            # parse the prices
            price_data = {}
            price_data["station_id"] = result["id"]
            price_data["unit_of_measure"] = result["priceUnit"]
            price_data["currency"] = result["currency"]
            price_data["latitude"] = result["latitude"]
            price_data["longitude"] = result["longitude"]

            for price in result["prices"]:
                index = price["fuelProduct"]
                if price["cash"]:
                    price_data[index] = {
                        "credit": price["credit"]["nickname"],
                        "cash_price": (
                            None
                            if price.get("cash", {}).get("price", 0) == 0
                            else price["cash"]["price"]
                        ),
                        "price": (
                            None
                            if price.get("credit", {}).get("price", 0) == 0
                            else price["credit"]["price"]
                        ),
                        "last_updated": price["credit"]["postedTime"],
                    }
                else:
                    price_data[index] = {
                        "credit": price["credit"]["nickname"],
                        "price": (
                            None
                            if price.get("credit", {}).get("price", 0) == 0
                            else price["credit"]["price"]
                        ),
                        "last_updated": price["credit"]["postedTime"],
                    }
            result_list.append(price_data)
        return result_list

    @backoff.on_exception(
        backoff.expo, aiohttp.ClientError, max_time=60, max_tries=MAX_RETRIES
    )
    async def _get_headers(self) -> None:
        """Get required headers if not using FlareSolverr."""
        if self._flaresolverr_url:
            _LOGGER.debug(
                "FlareSolverr is configured, _get_headers will not fetch token directly."
            )
            # If FlareSolverr is used, the token should be extracted from its responses.
            # We might still want to ensure self._tag has a value if a direct call happens after a failed FS attempt.
            # However, process_request logic should handle this.
            return

        _LOGGER.debug("FlareSolverr not configured, proceeding to fetch CSRF token directly.")
        # Original headers for the token fetching request
        fetch_headers = {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/137.0.0.0 Safari/537.36" # Consider using the one from consts or a more dynamic one
            ),
            "apollo-require-preflight": "true", # This might not be needed for a simple GET to /home
            "Origin": "https://www.gasbuddy.com",
            "Referer": "https://www.gasbuddy.com/home",
        }
        url = "https://www.gasbuddy.com/home"

        try:
            async with aiohttp.ClientSession(headers=fetch_headers) as session: # Use try-finally or ensure session is always closed
                try:
                    async with session.get(url, timeout=aiohttp.ClientTimeout(total=30)) as response:
                        message: str = ""
                        message = await response.text()
                        if response.status != 200:
                            _LOGGER.error(
                                "Error retrieving CSRF page, status: %s\nmessage: %s",
                                response.status,
                                message,
                            )
                            # Do not raise CSRFTokenMissing here, allow requests to proceed without if necessary,
                            # or let higher level backoff handle retries.
                            # For now, just log and return. The self._tag will remain empty.
                            return

                        pattern = re.compile(r'window\.gbcsrf\s*=\s*(["])(.*?)\1')
                        found = pattern.search(message)
                        if found is not None:
                            self._tag = found.group(2)
                            _LOGGER.debug("CSRF token found directly: %s", self._tag)
                        else:
                            _LOGGER.error("CSRF token not found in direct response from /home.")
                            # Do not raise CSRFTokenMissing here. self._tag remains empty.
                            # This allows process_request to proceed and potentially fail, which is then handled by backoff.
                            # raise CSRFTokenMissing # Original behavior

                except (TimeoutError, ServerTimeoutError, aiohttp.ClientError) as e: # Catch specific errors
                    _LOGGER.error("%s: %s while fetching CSRF token. Error: %s", CSRF_TIMEOUT, url, e)
                    # self._tag remains empty or unchanged.
        except Exception as e:
            # Catchall for other unexpected errors during session creation or other parts of _get_headers
            _LOGGER.error("Unexpected error in _get_headers: %s", e)

    async def close(self) -> None:
        """Clean up resources, especially the FlareSolverr session."""
        if self._flaresolverr_session_id and self._flaresolverr_url and self._flaresolverr_session:
            _LOGGER.debug(
                "Closing FlareSolverr session: %s", self._flaresolverr_session_id
            )
            payload = {
                "cmd": "sessions.destroy",
                "session": self._flaresolverr_session_id,
            }
            try:
                async with self._flaresolverr_session.post(
                    self._flaresolverr_url,
                    json=payload,
                    headers={"Content-Type": "application/json"},
                    timeout=aiohttp.ClientTimeout(total=30),
                ) as response:
                    response_data = await response.json()
                    if response.status == 200 and response_data.get("status") == "ok":
                        _LOGGER.info(
                            "FlareSolverr session %s destroyed successfully.",
                            self._flaresolverr_session_id,
                        )
                    else:
                        _LOGGER.warning(
                            "Failed to destroy FlareSolverr session %s. Status: %s, Response: %s",
                            self._flaresolverr_session_id,
                            response.status,
                            response_data,
                        )
            except aiohttp.ClientError as e:
                _LOGGER.warning(
                    "Error destroying FlareSolverr session %s: %s",
                    self._flaresolverr_session_id,
                    e,
                )
            except json.JSONDecodeError as e:
                _LOGGER.warning(
                    "Error decoding FlareSolverr session.destroy response: %s", e
                )

        if self._flaresolverr_session and not self._flaresolverr_session.closed:
            await self._flaresolverr_session.close()
            _LOGGER.debug("FlareSolverr aiohttp session closed.")
