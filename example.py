# gasbuddy_example.py
# make sure to run pip install -f requirements_example.txt before running this

import asyncio
import gasbuddy


async def main():
    """
    This script demonstrates basic usage of the gasbuddy library.
    It retrieves stations for a specified zip code,
    and prints the results.
    It also shows how to optionally use FlareSolverr.
    """

    # --- Configuration ---
    zip_code = "90210"  # Example zip code - Beverly Hills, CA

    # Set this to your FlareSolverr URL if you want to use it, otherwise set to None
    flaresolverr_instance_url = None  # Example: "http://localhost:8191/v1"
    # flaresolverr_instance_url = "http://localhost:8191/v1" # Uncomment to try with FlareSolverr

    gb = None  # Initialize gb to None for finally block
    try:
        # Initialize the GasBuddy API client
        # If flaresolverr_instance_url is provided, it will be used for requests.
        print(f"Initializing GasBuddy client. FlareSolverr URL: {flaresolverr_instance_url or 'Not used'}")
        gb = gasbuddy.GasBuddy(flaresolverr_url=flaresolverr_instance_url)

        print(f"\nSearching for stations in zip code {zip_code}...")
        stations_response = await gb.location_search(zipcode=zip_code)

        if stations_response and "data" in stations_response and \
           stations_response["data"].get("locationBySearchTerm", {}).get("stations", {}).get("results"):

            print(f"\nStations for Zip Code {zip_code}:")
            results = stations_response["data"]["locationBySearchTerm"]["stations"]["results"]
            for station in results:
                print(f"  - Station: {station.get('name', 'N/A')}")
                print(f"    Address: {station.get('address', {}).get('line1', 'N/A')}")
                print(f"    ID: {station.get('id', 'N/A')}")
                print("-" * 20)

            # Example: Get detailed price for the first station found (if any)
            if results:
                first_station_id = results[0].get("id")
                if first_station_id:
                    print(f"\nLooking up prices for station ID: {first_station_id}...")
                    # Re-initialize GasBuddy for a specific station ID if needed, or use existing
                    # For this example, let's create a new instance for price_lookup by ID
                    # (though you could modify the class to allow setting station_id later too)
                    gb_station_lookup = gasbuddy.GasBuddy(
                        station_id=int(first_station_id),
                        flaresolverr_url=flaresolverr_instance_url
                    )
                    try:
                        prices = await gb_station_lookup.price_lookup()
                        if prices:
                            print(f"Prices for station {first_station_id}:")
                            for fuel_type, details in prices.items():
                                if isinstance(details, dict): # regular_gas, premium_gas etc.
                                    print(f"  {fuel_type.replace('_', ' ').title()}:")
                                    print(f"    Price: {details.get('price')}")
                                    if "cash_price" in details:
                                        print(f"    Cash Price: {details.get('cash_price')}")
                                    print(f"    Last Updated: {details.get('last_updated')}")
                        else:
                            print(f"No price data found for station {first_station_id}.")
                    finally:
                        if gb_station_lookup:
                            await gb_station_lookup.close() # Close this specific instance
                    print("-" * 20)

        elif stations_response and "error" in stations_response:
            print(f"Error from GasBuddy: {stations_response['error']}")
        else:
            print(f"No stations found or unexpected response for zip code {zip_code}.")
            print(f"Full response: {stations_response}")


    except gasbuddy.MissingSearchData as e:
        print(f"An error occurred: {e}")
    except gasbuddy.APIError as e:
        print(f"A GasBuddy API error occurred: {e}")
    except gasbuddy.LibraryError as e:
        print(f"A library error occurred: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
    finally:
        if gb:
            print("\nClosing GasBuddy client...")
            await gb.close()
            print("GasBuddy client closed.")


if __name__ == "__main__":
    asyncio.run(main())
