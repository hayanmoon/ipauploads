import os
import sys
import argparse
import zipfile
import ntpath
import json
import time
import plistlib

TRANSIENT_HTTP_STATUSES = {408, 429, 500, 502, 503, 504}

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
        # Upload requests use tokens with a maximum lifetime of 20 minutes.
        issued_at = int(time.time())
        exp = issued_at + 1200
        payload = {"iss": issuer_id, "iat": issued_at, "exp": exp, "aud": "appstoreconnect-v1"}

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
    if response.status_code in TRANSIENT_HTTP_STATUSES:
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
                
        if response.status_code == 204 or not response.content:
            return {}
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

def check_existing_build(app_id, version, build, token_manager, client, dry_run=False):
    """Check iOS duplicates and clean pending reservations for serial CI uploads."""
    print(f"\n-> Checking if Version {version} (Build {build}) already exists...")
    
    # CI runs one uploader at a time, so pending reservations are from earlier runs.
    # Finish duplicate checks before deleting anything; dry runs remain read-only.
    pending_upload_ids = []
    upload_url = (
        f"https://api.appstoreconnect.apple.com/v1/apps/{app_id}/buildUploads"
        f"?filter[cfBundleShortVersionString]={version}&filter[cfBundleVersion]={build}"
        f"&filter[platform]=IOS"
    )
    while upload_url:
        upload_data = api_request('GET', upload_url, token_manager, client)
        for upload in upload_data.get('data', []):
            upload_id = upload.get('id')
            state_obj = upload.get('attributes', {}).get('state', {})
            state = state_obj.get('state') if isinstance(state_obj, dict) else state_obj
            print(f"   Found existing build upload ({upload_id}) in state: {state}")

            if state in ['AWAITING_UPLOAD', 'FAILED']:
                pending_upload_ids.append(upload_id)
            elif state in ['PROCESSING', 'COMPLETE']:
                print(f"   -> A build upload with this version/build number is already {state}. Skipping upload.")
                return True
            else:
                print(f"   Error: Cannot safely check duplicate upload with unknown state: {state!r}")
                sys.exit(1)
        upload_url = upload_data.get('links', {}).get('next')

    # 2. Check /v1/builds
    url = f"https://api.appstoreconnect.apple.com/v1/builds?filter[app]={app_id}&filter[version]={build}&filter[preReleaseVersion.version]={version}&filter[preReleaseVersion.platform]=IOS"
    while url:
        response_data = api_request('GET', url, token_manager, client)
        for existing_build in response_data.get('data', []):
            state = existing_build.get('attributes', {}).get('processingState')
            print(f"   Found existing build in state: {state}")
            if state in ['VALID', 'PROCESSING']:
                print("   -> A build with this version/build number is already processing or valid. Skipping upload.")
                return True
            elif state in ['FAILED', 'INVALID']:
                print(f"\n❌ Error: Build Version {version} (Build {build}) already exists in App Store Connect but is '{state}'.")
                print("   Apple permanently locks build numbers once processed. You MUST increment your build number for every new upload attempt.")
                sys.exit(1)
            else:
                print(f"   Error: Cannot safely check duplicate build with unknown state: {state!r}")
                sys.exit(1)
        url = response_data.get('links', {}).get('next')

    for upload_id in pending_upload_ids:
        if dry_run:
            print(f"   -> Dry run: would remove pending/failed reservation {upload_id} before uploading.")
        else:
            print(f"   -> Removing pending/failed reservation {upload_id} from an earlier CI run...")
            api_request('DELETE', f'https://api.appstoreconnect.apple.com/v1/buildUploads/{upload_id}', token_manager, client)
            print("   -> Pending/failed reservation removed.")

    return False

def wait_for_build_processing(version, build, build_upload_id, token_manager, client, timeout_minutes=45):
    """Polls /v1/buildUploads/{id} to wait for the build to finish processing.
    
    processingState values:
        AWAITING_UPLOAD  - waiting for file upload
        PROCESSING       - Apple is processing the build
        COMPLETE         - build processed successfully
        FAILED           - build processing failed
    """
    print(f"\nWaiting for App Store Connect to process Version {version} (Build {build}).")
    print(f"This typically takes 5-15 minutes. Polling every 30 seconds (Timeout: {timeout_minutes}m)...")
    
    build_upload_url = f"https://api.appstoreconnect.apple.com/v1/buildUploads/{build_upload_id}"
    start_time = time.monotonic()
    timeout_seconds = timeout_minutes * 60
    last_request_error = None
    last_state = 'PROCESSING'
    last_log_time = start_time
    
    while True:
        now = time.monotonic()
        if now - start_time >= timeout_seconds:
            if last_request_error:
                print(f"\nError: Timed out checking build status. Last request failed: {last_request_error}")
            else:
                print("\nError: Timed out waiting for build to process.")
                print(f"   Last known state in App Store Connect: {last_state}")
                print("   Note: The IPA was successfully uploaded and committed to Apple.")
                print("   Apple's backend ingestion is taking longer than usual.")
                print("   You can check the build status directly in App Store Connect.")
                print("   If you rerun this CI job after processing finishes, it will detect the build and succeed without re-uploading.")
            sys.exit(1)
            
        try:
            response_data = api_request('GET', build_upload_url, token_manager, client, timeout=10.0, exit_on_error=False)
            attrs = response_data['data']['attributes']
            state_obj = attrs['state']
            state = state_obj['state']
            if state not in ['AWAITING_UPLOAD', 'PROCESSING', 'COMPLETE', 'FAILED']:
                raise ValueError(f"Unexpected build upload state: {state!r}")
            last_request_error = None
            last_state = state
            
            def print_state_details(details, label):
                if details:
                    print(f"   {label}:")
                    for d in details:
                        code = d.get('code', 'UnknownCode')
                        desc = d.get('description', 'No description')
                        print(f"   - [{code}] {desc}")

            if state == 'COMPLETE':
                elapsed = int(time.monotonic() - start_time)
                mins, secs = divmod(elapsed, 60)
                print(f"\n\n✅ Build finished processing successfully! State: {state} (took {mins}m {secs:02d}s)")
                print_state_details(state_obj.get('warnings', []), "Warnings")
                print_state_details(state_obj.get('infos', []), "Info")
                return
            elif state == 'FAILED':
                elapsed = int(time.monotonic() - start_time)
                mins, secs = divmod(elapsed, 60)
                print(f"\n\n❌ Error: Build processing failed. State: {state} (after {mins}m {secs:02d}s)")
                print_state_details(state_obj.get('errors', []), "Error details")
                print_state_details(state_obj.get('warnings', []), "Warnings")
                print_state_details(state_obj.get('infos', []), "Info")
                sys.exit(1)
            else:
                # Log heartbeat periodically (every 60 seconds) so Jenkins console updates in real time
                now = time.monotonic()
                if now - last_log_time >= 60:
                    elapsed = int(now - start_time)
                    mins, secs = divmod(elapsed, 60)
                    print(f"   [{mins:02d}:{secs:02d} elapsed] Still processing in App Store Connect... (state: {state})", flush=True)
                    last_log_time = now
        except httpx.HTTPStatusError as e:
            if e.response.status_code not in TRANSIENT_HTTP_STATUSES:
                print(f"\nError: Cannot read build status (HTTP {e.response.status_code}): {e.response.text}")
                sys.exit(1)
            last_request_error = str(e)
            print(f"\n   Temporary API error (HTTP {e.response.status_code}); retrying...")
        except httpx.RequestError as e:
            last_request_error = str(e)
            print(f"\n   Temporary connection error: {e}; retrying...")
        except (ValueError, KeyError, TypeError, AttributeError) as e:
            print(f"\nError: Invalid build status response: {e}")
            sys.exit(1)
            
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
    matching_apps = [
        app for app in apps_data.get('data', [])
        if app.get('attributes', {}).get('bundleId') == bundle_id
    ]
    if not matching_apps:
        print(f"Error: Could not find an App in App Store Connect with Bundle ID '{bundle_id}'")
        sys.exit(1)
    
    app_id = matching_apps[0]['id']
    print(f"   Found App ID: {app_id}")

    # 1.5 Check for duplicate builds
    if check_existing_build(app_id, version, build, token_manager, client, dry_run=dry_run):
        print(f"\n✅ Build Version {version} (Build {build}) already exists in App Store Connect.")
        print("   Skipping upload (idempotent run).")
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
                print(f"Cleaning up incomplete upload reservation {build_upload_id} on Apple...")
                try:
                    api_request('DELETE', f'https://api.appstoreconnect.apple.com/v1/buildUploads/{build_upload_id}', token_manager, client, exit_on_error=False)
                    print("Cleaned up uncommitted reservation successfully.")
                except Exception as del_err:
                    print(f"Warning: Failed to clean up reservation: {del_err}")
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
    wait_for_build_processing(version, build, build_upload_id, token_manager, client)

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
