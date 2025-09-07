use axum::{
    extract::{Json, State},
    http::StatusCode,
    response::{Html, IntoResponse},
    routing::{get, post},
    Router,
};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::{net::SocketAddr, sync::{Arc, Mutex}};
use stellar_sdk::SecretKey;

mod ring;
mod soroban;

use ring::{Ring, RingSignature};

// --------------------------------------------------------------------------------
// Some build-time constants
static OPERATOR_SECRET: Lazy<SecretKey> =
    Lazy::new(|| SecretKey::from_encoding("SA....PUT_YOURS_HERE").unwrap());
static RPC_URL: &str = "https://soroban-testnet.stellar.org";

#[derive(Default)]
struct AppData {
    ring: Option<Ring>,
}

type Shared = Arc<Mutex<AppData>>;

// --------------------------------------------------------------------------------
#[tokio::main]
async fn main() {
    let state: Shared = Arc::new(Mutex::new(AppData::default()));

    let app = Router::new()
        .route("/", get(index))
        .route("/api/generate", post(generate))
        .route("/api/sign", post(sign))
        .with_state(state);

    let addr: SocketAddr = "0.0.0.0:8080".parse().unwrap();
    println!("listening on http://{addr}");
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}

// --------------------------------------------------------------------------------
async fn index() -> impl IntoResponse {
    Html(include_str!("../static/index.html"))
}

// --------------------------------------------------------------------------------
#[derive(Deserialize)]
struct GenerateReq {
    size: usize,
}
#[derive(Serialize)]
struct GenerateResp {
    ring: Vec<ring::PublicKey>,
}

async fn generate(
    State(shared): State<Shared>,
    Json(req): Json<GenerateReq>,
) -> impl IntoResponse {
    if req.size == 0 {
        return (StatusCode::BAD_REQUEST, "size must be > 0").into_response();
    }

    let ring = Ring::new(req.size);

    // Store in memory so that /sign can use it
    {
        let mut guard = shared.lock().unwrap();
        guard.ring = Some(ring.clone());
    }

    // also initialise the contract on-chain --------------------------------------
    let rpc = soroban_client::rpc::SorobanRpc::new(RPC_URL);
    if let Err(e) = soroban::init_if_needed(&rpc, &OPERATOR_SECRET, &ring).await {
        eprintln!("init() failed: {e:?}");
        return (StatusCode::INTERNAL_SERVER_ERROR, "init failed").into_response();
    }

    Json(GenerateResp { ring: ring.pks }).into_response()
}

// --------------------------------------------------------------------------------
#[derive(Deserialize)]
struct SignReq {
    message: String, // plain text
    wallet:  usize,  // index inside the ring
}
#[derive(Serialize)]
struct SignResp {
    signature: RingSignature,
}

async fn sign(
    State(shared): State<Shared>,
    Json(req): Json<SignReq>,
) -> impl IntoResponse {
    let Some(ring) = &shared.lock().unwrap().ring else {
        return (StatusCode::BAD_REQUEST, "generate the ring first").into_response();
    };
    if req.wallet >= ring.pks.len() {
        return (StatusCode::BAD_REQUEST, "wallet idx out of range").into_response();
    }
    let sig = ring.sign(req.message.as_bytes(), req.wallet);

    Json(SignResp { signature: sig }).into_response()
}