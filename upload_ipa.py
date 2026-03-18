import os
import sys
import argparse
import zipfile
import ntpath
import json
import time
import plistlib

try:
    import jwt
    import cryptography
    import httpx
    from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type
except ImportError:
    print("Error: PyJWT, cryptography, httpx, and tenacity libraries are required.")
    print("Install them using: pip install PyJWT cryptography httpx tenacity")
    sys.exit(1)

class TokenManager:
    """Manages App Store Connect JWT token generation and refreshing."""
    def __init__(self, api_key_data):
        self.api_key_data = api_key_data
        self.token = None
        self.token_exp = 0

    def get_token(self):
        # Refresh token if it's expiring in less than 2 minutes
        if time.time() > (self.token_exp - 120):
            self.token, self.token_exp = self._create_jwt_token()
        return self.token

    def _create_jwt_token(self):
        key_id = self.api_key_data.get('key_id')
        issuer_id = self.api_key_data.get('issuer_id')
        private_key = self.api_key_data.get('key')
        
        if not all([key_id, issuer_id, private_key]):
            print("Error: The provided API Key JSON is missing required fields.")
            print("It must contain 'key_id', 'issuer_id', and 'key' (the private key string).")
            sys.exit(1)

        headers = {"kid": key_id, "typ": "JWT"}
        # Per Apple documentation, tokens CANNOT live longer than 20 minutes (1200 seconds).
        exp = int(time.time()) + 1200
        payload = {"iss": issuer_id, "exp": exp, "aud": "appstoreconnect-v1"}

        try:
            token = jwt.encode(payload, private_key, algorithm="ES256", headers=headers)
            return token, exp
        except Exception as e:
            print(f"Error generating JWT token: {e}")
            sys.exit(1)

# Robust retry wrapper for Apple API requests
@retry(
    stop=stop_after_attempt(5),
    wait=wait_exponential(multiplier=1, min=2, max=16),
    retry=retry_if_exception_type((httpx.RequestError, httpx.HTTPStatusError)),
    reraise=True
)
def _execute_api_request(client, method, url, headers, json_data, timeout):
    response = client.request(method, url, headers=headers, json=json_data, timeout=timeout)
    # Manually raise exception for transient HTTP errors so tenacity retries them
    if response.status_code in [408, 429, 500, 502, 503, 504]:
        response.raise_for_status()
    return response

def api_request(method, url, token_manager, client, json_data=None, timeout=30.0, exit_on_error=True):
    """Helper method to make App Store Connect API calls with error parsing."""
    headers = {
        'Authorization': f'Bearer {token_manager.get_token()}',
        'Content-Type': 'application/json'
    }
    
    try:
        response = _execute_api_request(client, method, url, headers, json_data, timeout)
        
        if not response.is_success:
            if exit_on_error:
                print(f"API Error ({response.status_code}) on {method} {url}")
                try:
                    error_data = response.json()
                    for err in error_data.get('errors', []):
                        print(f" - {err.get('title', 'Error')}: {err.get('detail', 'No details provided')}")
                except Exception:
                    print(response.text)
                sys.exit(1)
            else:
                response.raise_for_status()
                
        return response.json()
    except Exception as e:
        if exit_on_error:
            print(f"Network error during API request to {url}: {e}")
            sys.exit(1)
        raise

def get_ipa_metadata(ipa_path):
    """Extracts the Bundle ID, Version, and Build Number from the IPA file's Info.plist."""
    try:
        with zipfile.ZipFile(ipa_path, 'r') as z:
            plist_path = None
            for name in z.namelist():
                if name.startswith('Payload/') and name.endswith('.app/Info.plist') and name.count('/') == 2:
                    plist_path = name
                    break
                    
            if not plist_path:
                print(f"Error: Could not find Info.plist inside {ipa_path}")
                sys.exit(1)
            
            with z.open(plist_path) as f:
                if hasattr(plistlib, 'load'):
                    plist = plistlib.load(f)
                else:
                    plist = plistlib.readPlist(f)
                
            bundle_id = plist.get('CFBundleIdentifier')
            version = plist.get('CFBundleShortVersionString')
            build = plist.get('CFBundleVersion')
            
            if not all([bundle_id, version, build]):
                print(f"Error: Incomplete metadata in Info.plist. Found BundleID: {bundle_id}, Version: {version}, Build: {build}")
                sys.exit(1)
                
            return bundle_id, version, build
    except Exception as e:
        print(f"Error parsing IPA file: {e}")
        sys.exit(1)

def check_existing_build(app_id, version, build, token_manager, client):
    """Checks if a build with the exact version and build number already exists."""
    print(f"\n-> Checking if Version {version} (Build {build}) already exists...")
    url = f"https://api.appstoreconnect.apple.com/v1/builds?filter[app]={app_id}&filter[version]={build}&filter[preReleaseVersion.version]={version}"
    response_data = api_request('GET', url, token_manager, client)
    
    builds = response_data.get('data', [])
    if builds:
        state = builds[0].get('attributes', {}).get('processingState')
        print(f"   Found existing build in state: {state}")
        if state in ['VALID', 'PROCESSING']:
            print("   -> A build with this version/build number is already processing or valid. Skipping upload.")
            return True
        else:
            print(f"   -> Error: A build with this version/build number exists but is in state '{state}'.")
            print("      Apple requires you to increment your build number for every new upload attempt.")
            sys.exit(1)
            
    return False

def wait_for_build_processing(app_id, version, build, token_manager, client, timeout_minutes=45):
    """Polls the API to wait for the build to finish processing."""
    print(f"\nWaiting for App Store Connect to process Version {version} (Build {build}).")
    print(f"This typically takes 5-15 minutes. Polling every 30 seconds (Timeout: {timeout_minutes}m)...")
    
    url = f"https://api.appstoreconnect.apple.com/v1/builds?filter[app]={app_id}&filter[version]={build}&filter[preReleaseVersion.version]={version}"
    
    start_time = time.time()
    timeout_seconds = timeout_minutes * 60
    
    while True:
        if time.time() - start_time > timeout_seconds:
            print("\nError: Timed out waiting for build to process.")
            sys.exit(1)
            
        sys.stdout.write('.')
        sys.stdout.flush()
        
        try:
            # We set exit_on_error=False to prevent a transient 502 from killing our poll loop
            response_data = api_request('GET', url, token_manager, client, timeout=10.0, exit_on_error=False)
            builds = response_data.get('data', [])
            
            if builds:
                state = builds[0].get('attributes', {}).get('processingState')
                
                if state == 'VALID':
                    print(f"\n\n✅ Build finished processing successfully! State: {state}")
                    return
                elif state in ['FAILED', 'INVALID']:
                    print(f"\n\n❌ Error: Build processing failed. State: {state}")
                    sys.exit(1)
            
        except Exception:
            # Swallow transient network errors and json decoding issues to keep polling alive
            pass
            
        time.sleep(30)

# Robust retry wrapper for binary chunk uploads
@retry(
    stop=stop_after_attempt(5),
    wait=wait_exponential(multiplier=1, min=2, max=16),
    retry=retry_if_exception_type((httpx.RequestError, httpx.HTTPStatusError)),
    reraise=True
)
def upload_chunk_with_retry(client, upload_url, op_headers, chunk_data):
    response = client.put(upload_url, headers=op_headers, content=chunk_data, timeout=60.0)
    response.raise_for_status()
    return response

def upload_ipa_v1_api(ipa_path, token_manager, client, dry_run=False):
    """Uploads the IPA file using the native /v1/buildUploads API endpoint."""
    if not os.path.isfile(ipa_path):
        print(f"Error: IPA file '{ipa_path}' not found or is not a file.")
        sys.exit(1)

    print(f"Parsing IPA metadata for: {ipa_path}...")
    bundle_id, version, build = get_ipa_metadata(ipa_path)
    print(f"Detected App Metadata -> Bundle ID: {bundle_id} | Version: {version} | Build: {build}")

    # 1. Resolve Apple App ID from Bundle ID
    print(f"\n1. Looking up App ID for {bundle_id}...")
    apps_data = api_request('GET', f'https://api.appstoreconnect.apple.com/v1/apps?filter[bundleId]={bundle_id}', token_manager, client)
    if not apps_data.get('data'):
        print(f"Error: Could not find an App in App Store Connect with Bundle ID '{bundle_id}'")
        sys.exit(1)
    
    app_id = apps_data['data'][0]['id']
    print(f"   Found App ID: {app_id}")

    # 1.5 Check for duplicate builds
    if check_existing_build(app_id, version, build, token_manager, client):
        print("\n✅ Skipping upload as build already exists.")
        sys.exit(0)

    if dry_run:
        print("\n✅ DRY RUN SUCCESSFUL!")
        print("   Apple App Store Connect API authentication is valid.")
        print("   IPA metadata is valid and successfully extracted.")
        print("   App ID mapping matches successfully.")
        print("   Duplicate check passed cleanly.")
        print("   -> Exiting early without pushing buildUploads data.")
        sys.exit(0)

    # 2. Create Build Upload Resource
    print(f"\n2. Creating Build Upload resource...")
    platform = "IOS" 
    
    create_build_payload = {
        "data": {
            "type": "buildUploads",
            "attributes": {
                "cfBundleShortVersionString": str(version),
                "cfBundleVersion": str(build),
                "platform": platform
            },
            "relationships": {
                "app": {
                    "data": {
                        "type": "apps",
                        "id": app_id
                    }
                }
            }
        }
    }
    
    build_upload_response = api_request('POST', 'https://api.appstoreconnect.apple.com/v1/buildUploads', token_manager, client, create_build_payload)
    build_upload_id = build_upload_response['data']['id']
    print(f"   Created Build Upload ID: {build_upload_id}")

    # 3. Create Reservation for Build Upload File
    print(f"\n3. Reserving file storage...")
    file_size = os.path.getsize(ipa_path)
    file_name = ntpath.basename(ipa_path)
    
    reserve_file_payload = {
        "data": {
            "type": "buildUploadFiles",
            "attributes": {
                "assetType": "ASSET",
                "fileName": file_name,
                "fileSize": file_size,
                "uti": "com.apple.ipa"
            },
            "relationships": {
                "buildUpload": {
                    "data": {
                        "type": "buildUploads",
                        "id": build_upload_id
                    }
                }
            }
        }
    }
    
    file_reservation_response = api_request('POST', 'https://api.appstoreconnect.apple.com/v1/buildUploadFiles', token_manager, client, reserve_file_payload)
    file_id = file_reservation_response['data']['id']
    upload_operations = file_reservation_response['data']['attributes']['uploadOperations']
    
    # 4. Perform the Chunked Upload
    print(f"\n4. Uploading file ({file_size} bytes) in {len(upload_operations)} chunks...")
    
    with open(ipa_path, 'rb') as f:
        for idx, operation in enumerate(upload_operations):
            offset = operation['offset']
            length = operation['length']
            upload_url = operation['url']
            op_headers = {h['name']: h['value'] for h in operation['requestHeaders']}
            
            f.seek(offset)
            chunk_data = f.read(length)
            
            print(f"   -> Uploading chunk {idx+1}/{len(upload_operations)} (offset: {offset}, length: {len(chunk_data)})...")
            
            try:
                upload_chunk_with_retry(client, upload_url, op_headers, chunk_data)
            except Exception as e:
                print(f"Error: Failed to upload chunk {idx+1} after retries: {e}")
                sys.exit(1)
                
    print("   All chunks uploaded successfully.")

    # 5. Commit the Build Upload File
    print(f"\n5. Committing build upload...")
    commit_payload = {
        "data": {
            "id": file_id,
            "type": "buildUploadFiles",
            "attributes": {
                "uploaded": True
            }
        }
    }
    
    api_request('PATCH', f'https://api.appstoreconnect.apple.com/v1/buildUploadFiles/{file_id}', token_manager, client, commit_payload)
    
    print("\n✅ Upload completed successfully!")
    print("The build is now processing in App Store Connect.")
    
    # 6. Wait for Processing to Complete
    wait_for_build_processing(app_id, version, build, token_manager, client)

def main():
    parser = argparse.ArgumentParser(
        description="Upload an IPA file directly to App Store Connect using the native v1/buildUploads API.",
        epilog="Ensure your App Store Connect API credentials are set via environment variables or a JSON file."
    )
    parser.add_argument("ipa_path", help="Path to the .ipa file you want to upload.")
    parser.add_argument("--api-key", help="Path to the Fastlane-style API Key JSON file.")
    parser.add_argument("--dry-run", action="store_true", help="Validate credentials and metadata, but halt before actually uploading.")

    args = parser.parse_args()

    # Determine Key Path (Arg takes precedence over Env)
    json_key_path = args.api_key or os.environ.get("APPSTORE_API_KEY_JSON")

    if not json_key_path:
        print("Error: App Store Connect API Key JSON not provided.")
        print("Please provide it via the --api-key argument or export APPSTORE_API_KEY_JSON='/path/to/key.json'")
        sys.exit(1)

    if not os.path.exists(json_key_path):
        print(f"Error: API Key JSON file not found at '{json_key_path}'")
        sys.exit(1)

    try:
        with open(json_key_path, 'r') as f:
            api_key_data = json.load(f)
    except Exception as e:
        print(f"Error reading '{json_key_path}': {e}")
        sys.exit(1)

    print("Authenticating with App Store Connect...")
    token_manager = TokenManager(api_key_data)
    
    # Use httpx.Client to reuse connections and wrap with tenacity retries
    with httpx.Client() as client:
        upload_ipa_v1_api(args.ipa_path, token_manager, client, dry_run=args.dry_run)

if __name__ == "__main__":
    main()
