// Copyright © Aptos Foundation
// SPDX-License-Identifier: Apache-2.0

use aptos_crypto::{ed25519::Ed25519PrivateKey, PrivateKey, Uniform};
use aptos_infallible::duration_since_epoch;
use aptos_keyless_pepper_common::{
    account_recovery_db::AccountRecoveryDbEntry,
    jwt,
    vuf::{self, VUF},
    PepperInput, PepperRequest, PepperResponse, PepperV0VufPubKey, SignatureResponse,
};
use aptos_types::{
    keyless::{Configuration, OpenIdSig},
    transaction::authenticator::EphemeralPublicKey,
};
use ark_bls12_381::G2Projective;
use ark_serialize::CanonicalDeserialize;
use firestore::{path, paths, FirestoreDb, FirestoreDbOptions};
use rand::RngCore;
use reqwest::{Client, StatusCode};
use serde::Serialize;
use std::{fs, io::stdin, time::Duration};

// Environment variables
const ENV_PEPPER_SERVICE_URL: &str = "PEPPER_SERVICE_URL";
const ENV_GOOGLE_PROJECT_ID: &str = "PROJECT_ID";
const ENV_FIRESTORE_DATABASE_ID: &str = "DATABASE_ID";

// Default values
const DEFAULT_CLIENT_TIMEOUT_SECS: u64 = 10;
const DEFAULT_FIRESTORE_COLLECTION: &str = "accounts";
const DEFAULT_JWT: &str =
    "eyJhbGciOiJSUzI1NiIsImtpZCI6ImUxYjkzYzY0MDE0NGI4NGJkMDViZjI5NmQ2NzI2MmI2\
     YmM2MWE0ODciLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZ\
     S5jb20iLCJhenAiOiI0MDc0MDg3MTgxOTIuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iL\
     CJhdWQiOiI0MDc0MDg3MTgxOTIuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJzdWIiO\
     iIxMTE2Mjc3NzI0NjA3NTIzNDIzMTIiLCJhdF9oYXNoIjoiaG5OWHFJVTZ3dWFPYlVqR05lR\
     VhGQSIsIm5vbmNlIjoiNzQyMDQxODMxNDYwMDk1MDM0MTU3NzQ0MzEzMzY0MTU4OTk0NzYwN\
     TExMjc1MDEwNDIyNjY5MDY3NTc3OTY3NTIyNDAwNjA0OTI0NCIsIm5hbWUiOiJPbGl2ZXIgS\
     GUiLCJnaXZlbl9uYW1lIjoiT2xpdmVyIiwiZmFtaWx5X25hbWUiOiJIZSIsImlhdCI6MTcxN\
     DQ0MTc4MywiZXhwIjoxNzE0NDQ1MzgzfQ.iNeVzp4BTQj2I_WH6UaUOfUBV4Q_wUriV7jWkh\
     1fUqTPSs30jMMSjEDZml8lQ_NUIpivnGvfEHt_rF9rlrsuRur9pTVKRRKhJUNf5avrAujvLz\
     rz-bwdgKXtTY_nmYisNNNQwmFIVP004ICois4DHD7EmO8PI88CzSzdDbl9qAIoxOP3JRKRwU\
     05wK5qkGz6FpYzTYiG50lQCybSzzUN5Lws49ANCAOZiROG5lmszOW41mAbFSd6MUX469uvyM\
     A2ZZ5av9ArKricHJPutGtLoOSWpzKQ_mlCzofVs5tHoMhGgcOFKuhnEVdY4J7TdcV6pZv9Ih\
     5F8MX3-Wz9Iz9O4w";
const DEFAULT_PEPPER_SERVICE_URL: &str = "http://localhost:8000";
const DEFAULT_UID_KEY: &str = "sub";

// Endpoints for the pepper service
const PEPPER_SERVICE_FETCH_URL: &str = "/v0/fetch";
const PEPPER_SERVICE_SIG_URL: &str = "/v0/signature";
const PEPPER_SERVICE_VUF_PUB_KEY_URL: &str = "/v0/vuf-pub-key";

// Useful type annotations
type Blinder = [u8; 31];

/// Runs the example client that interacts with the pepper service
pub async fn run_example_client() {
    print(
        "Starting the example client that interacts with the Aptos OIDB Pepper Service.",
        true,
    );

    // Step 1: Fetch the verification key from the pepper service
    let pepper_service_url = get_pepper_service_url();
    let mut request_client = create_request_client();
    let verification_public_key =
        fetch_verification_public_key(&mut request_client, &pepper_service_url).await;

    // Step 2: Create the blinder, ephemeral key and ephemeral key expiry time
    let (blinder, ephemeral_public_key, ephemeral_key_expiry_secs) =
        generate_blinder_and_ephemeral_key();

    // Step 3: Generate an OAuth nonce using the blinder, ephemeral public key and expiry time
    let nonce_str = generate_oauth_nonce(blinder, ephemeral_key_expiry_secs, &ephemeral_public_key);

    // Step 4: Fetch a JWT with the given nonce
    let jwt = fetch_jwt_with_nonce(nonce_str);

    // Step 5: Request a pepper from the pepper service
    let (pepper_request, pepper, address) = request_pepper_from_service(
        &mut request_client,
        &pepper_service_url,
        blinder,
        ephemeral_public_key,
        ephemeral_key_expiry_secs,
        &jwt,
    )
    .await;

    // Step 6: Request a signature from the pepper service for the pepper request
    let signature = request_signature_from_service(
        &mut request_client,
        &pepper_service_url,
        &pepper_request,
        pepper,
        address,
    )
    .await;

    // (Optional) Step 7: Verify the pepper signature using the verification key, JWT and signature
    let pepper_input = verify_pepper_signature(&verification_public_key, jwt, &signature);

    // (Optional) Step 8: Verify the firestore entry for the pepper input
    verify_firestore_pepper_entry(pepper_input).await;
}

/// Fetches a JWT with the given nonce
fn fetch_jwt_with_nonce(nonce_str: String) -> String {
    print(
        &format!("Step 4: Fetch a JWT with the given nonce: {}", nonce_str),
        true,
    );

    // Print instructions for the user to follow
    print("To fetch a JWT with the nonce, we will use an example from the Google OAuth 2.0 Playground.", false);
    print("First, open the following URL in your web browser:", false);
    print(
        &format!(
            "https://accounts.google.com/o/oauth2/v2/auth/oauthchooseaccount?\
                  redirect_uri=https%3A%2F%2Fdevelopers.google.com%2Foauthplayground\
                  &prompt=consent\
                  &response_type=code\
                  &client_id=407408718192.apps.googleusercontent.com\
                  &scope=profile\
                  &access_type=offline\
                  &service=lso\
                  &o2v=2\
                  &theme=glif\
                  &flowName=GeneralOAuthFlow\
                  &nonce={}",
            nonce_str
        ),
        false,
    );
    print("Then, sign in as requested by the web UI.", false);
    print(
        "Once you are signed in to 'OAuth 2.0 Playground' click the blue button called \
                 'Exchange authorization code for tokens'.",
        false,
    );
    print(
        "You should see a response. In the response, take the value of the field 'id_token' \
                    (exclude the double-quotes) and save it to a file. This is your JWT.",
        false,
    );

    // Get the JWT from the user
    get_jwt()
}

/// Creates and returns a new reqwest client
fn create_request_client() -> Client {
    Client::builder()
        .timeout(Duration::from_secs(DEFAULT_CLIENT_TIMEOUT_SECS))
        .build()
        .unwrap()
}

/// Fetches the verification key from the pepper service
async fn fetch_verification_public_key(
    request_client: &mut Client,
    pepper_service_url: &str,
) -> G2Projective {
    let verification_key_url = format!("{}{}", pepper_service_url, PEPPER_SERVICE_VUF_PUB_KEY_URL);
    print(
        &format!("Step 1: Fetching the verification key from the pepper service with a GET request to {}.", verification_key_url),
        true,
    );

    // Send the GET request
    let response = request_client
        .get(verification_key_url)
        .send()
        .await
        .unwrap();

    // Parse the verification key from the response
    let verification_key = response.json::<PepperV0VufPubKey>().await.unwrap();
    print(
        &format!(
            "Received the verification key: {}",
            to_string_pretty(&verification_key)
        ),
        false,
    );

    // Deserialize the verification key
    ark_bls12_381::G2Affine::deserialize_compressed(verification_key.public_key.as_slice())
        .unwrap()
        .into()
}

/// Generates a blinder, an ephemeral key pair, and an expiry time for the ephemeral key
fn generate_blinder_and_ephemeral_key() -> (Blinder, EphemeralPublicKey, u64) {
    print(
        "Step 2: Generating a blinder, ephemeral keypair and keypair expiration time.",
        true,
    );

    // Generate a random blinder
    let mut blinder = Blinder::default();
    rand::thread_rng().fill_bytes(&mut blinder);
    print(
        &format!("Generated blinder (hex): {}", hex::encode(blinder)),
        false,
    );

    // Generate a new ephemeral key pair
    let private_key = Ed25519PrivateKey::generate(&mut rand::thread_rng());
    let ephemeral_public_key = EphemeralPublicKey::ed25519(private_key.public_key());
    print(
        &format!(
            "Generated ephemeral public key (hex): {} and private key (hex): {}",
            hex::encode(ephemeral_public_key.to_bytes()),
            hex::encode(private_key.to_bytes())
        ),
        false,
    );

    // Generate a UNIX expiry time for the keypair (e.g., 1 hour from now)
    let expiry_time_secs = duration_since_epoch().as_secs() + 3600;
    print(
        &format!(
            "Generated UNIX expiry time (1 hour from now): {}",
            expiry_time_secs
        ),
        false,
    );

    (blinder, ephemeral_public_key, expiry_time_secs)
}

/// Generates the OAuth nonce using the given blinder, expiry time, and ephemeral public key
fn generate_oauth_nonce(
    blinder: Blinder,
    epk_expiry_time_secs: u64,
    ephemeral_public_key: &EphemeralPublicKey,
) -> String {
    print(
        "Step 3: Generating the OAuth nonce using the blinder, expiry time, and ephemeral public key.",
        true,
    );

    // Generate the nonce
    let oauth_nonce = OpenIdSig::reconstruct_oauth_nonce(
        blinder.as_slice(),
        epk_expiry_time_secs,
        ephemeral_public_key,
        &get_keyless_configuration(),
    )
    .unwrap();
    print(&format!("Generated OAuth nonce: {}", oauth_nonce), false);

    oauth_nonce
}

/// Returns a keyless configuration (in this case, for devnet)
fn get_keyless_configuration() -> Configuration {
    Configuration::new_for_devnet()
}

/// Fetches the pepper service URL from the environment variable or prompts the user for input
fn get_pepper_service_url() -> String {
    // Fetch the URL from the environment variable (if it exists)
    if let Ok(pepper_service_url) = std::env::var(ENV_PEPPER_SERVICE_URL) {
        print(
            &format!(
                "Pepper service url found from environment variable ({}): {}",
                ENV_PEPPER_SERVICE_URL, pepper_service_url
            ),
            false,
        );
        return pepper_service_url;
    }

    // Otherwise, prompt the user for input
    print(
        &format!(
            "Pepper service url not found from environment variable ({}). Enter the URL of the \
        pepper service deployment. If nothing is entered, the default will be used ({}).",
            ENV_PEPPER_SERVICE_URL, DEFAULT_PEPPER_SERVICE_URL
        ),
        false,
    );
    let user_input = read_input_from_stdin();
    let pepper_service_url = if user_input.is_empty() {
        DEFAULT_PEPPER_SERVICE_URL.to_string()
    } else {
        user_input
    };

    print(
        &format!("Using pepper service url: {}", pepper_service_url),
        false,
    );
    pepper_service_url
}

/// Fetches the JWT from the user, or uses a test token if no input is provided
fn get_jwt() -> String {
    // Prompt the user for the token or file path
    print(
        "Enter the JWT, or a text file path that contains the JWT. If nothing is entered, \
    a test token will be used.",
        true,
    );
    let user_input = read_input_from_stdin().trim().to_string();

    // Fetch the JWT or use the test token
    if !user_input.is_empty() {
        match fs::read_to_string(user_input.clone()) {
            Ok(jwt) => {
                print("Read the JWT from the file!", false);
                jwt.trim().to_string()
            },
            Err(_) => {
                print("Using the input as the JWT itself!", false);
                user_input
            },
        }
    } else {
        print("Using the test JWT token!", false);
        DEFAULT_JWT.to_string()
    }
}

/// Prints the given string. If `newline_header` is true, adds an empty line before the string.
fn print(string: &str, newline_header: bool) {
    if newline_header {
        println!();
    }
    println!("{}", string);
}

/// Reads a line from stdin and returns it as string
fn read_input_from_stdin() -> String {
    let mut line = String::new();
    stdin().read_line(&mut line).unwrap();
    line.trim().to_string()
}

/// Requests a pepper from the pepper service for the given parameters
async fn request_pepper_from_service(
    request_client: &mut Client,
    pepper_service_url: &str,
    blinder: Blinder,
    ephemeral_public_key: EphemeralPublicKey,
    ephemeral_key_expiry_secs: u64,
    jwt: &str,
) -> (PepperRequest, Vec<u8>, Vec<u8>) {
    let pepper_fetch_url = format!("{}{}", pepper_service_url, PEPPER_SERVICE_FETCH_URL);
    print(
        &format!(
            "Step 5: Requesting a pepper from the pepper service with a POST request to {}.",
            pepper_fetch_url
        ),
        true,
    );

    // Create the pepper request
    let pepper_request = PepperRequest {
        jwt: jwt.into(),
        epk: ephemeral_public_key,
        exp_date_secs: ephemeral_key_expiry_secs,
        uid_key: None,
        epk_blinder: blinder.to_vec(),
        derivation_path: None,
    };

    // Send the request to fetch the pepper
    print(
        &format!(
            "Sending the request to fetch the pepper. Request body: {}",
            to_string_pretty(&pepper_request)
        ),
        false,
    );
    let response = request_client
        .post(pepper_fetch_url)
        .json(&pepper_request)
        .send()
        .await
        .unwrap();

    // Parse the response
    let pepper_response = match response.status() {
        StatusCode::OK => response.json::<PepperResponse>().await.unwrap(),
        status => {
            panic!(
                "Failed to fetch the pepper from the service. Response status: {}",
                status
            );
        },
    };
    print(
        &format!(
            "Received the pepper response from the service: {}",
            to_string_pretty(&pepper_response)
        ),
        false,
    );

    let PepperResponse { pepper, address } = pepper_response;
    (pepper_request, pepper, address)
}

/// Requests a signature from the pepper service for the given pepper request
async fn request_signature_from_service(
    request_client: &mut Client,
    pepper_service_url: &str,
    pepper_request: &PepperRequest,
    pepper: Vec<u8>,
    address: Vec<u8>,
) -> Vec<u8> {
    let pepper_sig_url = format!("{}{}", pepper_service_url, PEPPER_SERVICE_SIG_URL);
    print(
        &format!(
            "Step 6: Requesting a signature from the pepper service with a POST request to {}.",
            pepper_sig_url
        ),
        true,
    );

    // Send the request to fetch the signature
    print(
        &format!(
            "Sending the request to fetch the signature. Request body: {}",
            to_string_pretty(&pepper_request)
        ),
        false,
    );
    let response = request_client
        .post(pepper_sig_url)
        .json(&pepper_request)
        .send()
        .await
        .unwrap();

    // Parse the response
    let signature_response = match response.status() {
        StatusCode::OK => response.json::<SignatureResponse>().await.unwrap(),
        status => {
            panic!(
                "Failed to fetch the signature from the service. Response status: {}",
                status
            );
        },
    };
    print(
        &format!(
            "Received the signature response from the service: {}",
            to_string_pretty(&signature_response)
        ),
        false,
    );

    // Display the signature, pepper and address in hex format
    let SignatureResponse { signature } = signature_response;
    print(
        &format!("Signature (hex): {}", hex::encode(&signature)),
        false,
    );
    print(&format!("Pepper (hex): {}", hex::encode(&pepper)), false);
    print(&format!("Address (hex): {}", hex::encode(&address)), false);

    signature
}

/// Serializes a value to a pretty JSON string
fn to_string_pretty<T: ?Sized + Serialize>(value: &T) -> String {
    serde_json::to_string_pretty(value).unwrap()
}

/// Verifies that a firestore entry exists for the given pepper input
async fn verify_firestore_pepper_entry(pepper_input: PepperInput) {
    print(
        "Step 8: Verifying that a firestore entry exists for the given pepper input.",
        true,
    );

    // Fetch the project and database IDs from environment variables
    let google_project_id = std::env::var(ENV_GOOGLE_PROJECT_ID).unwrap();
    let database_id = std::env::var(ENV_FIRESTORE_DATABASE_ID).unwrap();

    // Create the firestore DB client
    let firestore_db_options = FirestoreDbOptions {
        google_project_id,
        database_id,
        max_retries: 1,
        firebase_api_url: None,
    };
    let firestore_db = FirestoreDb::with_options(firestore_db_options)
        .await
        .unwrap();

    // Query the firestore DB for the pepper input entry
    let docs: Vec<AccountRecoveryDbEntry> = firestore_db
        .fluent()
        .select()
        .fields(paths!(AccountRecoveryDbEntry::{iss, aud, uid_key, uid_val, last_request_unix_ms, first_request_unix_ms_minus_1q, num_requests}))
        .from(DEFAULT_FIRESTORE_COLLECTION)
        .filter(|q| {
            q.for_all([
                q.field(path!(AccountRecoveryDbEntry::iss))
                    .eq(pepper_input.iss.clone()),
                q.field(path!(AccountRecoveryDbEntry::aud))
                    .eq(pepper_input.aud.clone()),
                q.field(path!(AccountRecoveryDbEntry::uid_key))
                    .eq(pepper_input.uid_key.clone()),
                q.field(path!(AccountRecoveryDbEntry::uid_val))
                    .eq(pepper_input.uid_val.clone()),
            ])
        })
        .obj()
        .query()
        .await
        .unwrap();

    // Verify that exactly one entry was found
    match docs.len() {
        0 => panic!(
            "No firestore entry found for the given pepper input: {}",
            to_string_pretty(&pepper_input)
        ),
        1 => print(
            &format!(
                "Successfully found exactly one firestore entry for the given pepper input: {:?}",
                docs
            ),
            false,
        ),
        n => panic!(
            "Multiple ({}) firestore entries found for the given pepper input!",
            n
        ),
    }
}

/// Verifies the pepper signature using the verification public key, JWT and signature
fn verify_pepper_signature(
    verification_public_key: &G2Projective,
    jwt: String,
    signature: &[u8],
) -> PepperInput {
    print(
        "Step 7: Verifying the pepper signature using the verification public key, JWT and signature.",
        true,
    );

    // Parse the claims from the JWT
    let claims = jwt::parse(&jwt).unwrap();
    let iss = claims.claims.iss.clone();
    let uid_key = DEFAULT_UID_KEY.to_string();
    let uid_val = claims.claims.sub.clone();
    let aud = claims.claims.aud.clone();

    // Construct the pepper input and serialize it
    let pepper_input = PepperInput {
        iss,
        uid_key,
        uid_val,
        aud,
    };
    print(
        &format!(
            "Constructed the pepper input to verify the signature: {}",
            to_string_pretty(&pepper_input)
        ),
        false,
    );
    let pepper_input_bytes = bcs::to_bytes(&pepper_input).unwrap();

    // Verify the pepper service signature over the pepper input
    vuf::bls12381_g1_bls::Bls12381G1Bls::verify(
        verification_public_key,
        &pepper_input_bytes,
        signature,
        &[],
    )
    .unwrap();
    print(
        "The signature over the pepper input was verified successfully!",
        false,
    );

    pepper_input
}
