// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: AGPL-3.0-only

use attestation::crypto::{CertReqInfoExt, PrivateKeyInfoExt};
use attestation::snp;

use anyhow::Result;
use clap::{Parser, ValueEnum};
use const_oid::{
    db::rfc5912::{ID_EXTENSION_REQ, SECP_384_R_1},
    ObjectIdentifier,
};
use der::{AnyRef, Decode, Encode};
use http::header::CONTENT_TYPE;
use http::request::Request;
use http::StatusCode;
use hyper::{body::HttpBody, Body, Client, Uri};
use sec1::pkcs8::PrivateKeyInfo;
use std::fmt;
use std::fmt::Formatter;
use std::str::FromStr;
use std::sync::{Arc, RwLock};
use std::thread::sleep;
use std::time::{Duration, SystemTime};
use x509::{
    attr::Attribute,
    ext::Extension,
    name::RdnSequence,
    request::{CertReqInfo, ExtensionReq},
    Certificate,
};

const OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.58270.1.3");
const PKCS10: &str = "application/pkcs10";
const SLEEP: Duration = Duration::new(0, 100);

#[derive(Parser, Clone, Eq, PartialEq, Debug, ValueEnum)]
enum What {
    Crypto,
    Connections,
    Both,
}

#[derive(Clone, Debug, Parser)]
struct Cli {
    #[clap(
        short,
        long,
        env = "STRESS_URL",
        default_value = "http://localhost:3000"
    )]
    url: String,

    #[clap(value_enum, long, env = "STRESS_WHAT", default_value = "connections")]
    what: What,

    #[clap(short, long, env = "STRESS_ITERS", default_value = "10000")]
    iters: u32,

    #[clap(short, long, env = "STRESS_WORKERS", default_value = "8")]
    workers: u8,
}

#[derive(Debug)]
struct State {
    completed_counter: u32,
    error_counter: u32,
    bytes_out: u64,
    bytes_in: u64,
    sleep_duration: Duration,
    what: What,
    start: SystemTime,
}

impl State {
    pub fn new(what: &What) -> State {
        State {
            completed_counter: 0,
            error_counter: 0,
            bytes_out: 0,
            bytes_in: 0,
            sleep_duration: Duration::new(0, 0),
            what: what.clone(),
            start: SystemTime::now(),
        }
    }

    pub fn add_bytes(&mut self, b_in: u64, b_out: u64) {
        self.bytes_in += b_in;
        self.bytes_out += b_out;
    }

    pub fn inc_completed(&mut self) {
        self.completed_counter += 1;
    }

    pub fn inc_error(&mut self) {
        self.error_counter += 1;
    }

    pub fn reset(&mut self) {
        self.completed_counter = 0;
        self.error_counter = 0;
        self.bytes_out = 0;
        self.bytes_in = 0;
        self.sleep_duration = Duration::new(0, 0);
        self.start = SystemTime::now();
    }

    pub fn sleep(&mut self) {
        sleep(SLEEP);
        self.sleep_duration += SLEEP;
    }
}

impl fmt::Display for State {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let mode = match self.what {
            What::Crypto => "attestations",
            What::Connections => "connections",
            What::Both => "connections", // shouldn't happen
        };
        let duration = self.start.elapsed().unwrap();
        let seconds = duration.as_secs_f64();
        let sleep_seconds = self.sleep_duration.as_secs_f64();
        let iter_per_sec = if seconds > 0f64 {
            self.completed_counter as f64 / (seconds - sleep_seconds)
        } else {
            // prevent "inf"
            self.completed_counter as f64
        };
        #[cfg(debug_assertions)]
        return write!(f, "{} {} in {:.2} seconds\n{:.2} {}/sec\nBytes in/out: {}/{}\nKBytes in/out: {:.2}/{:.2}\nKBytes/sec in/out: {:.2}/{:.2}\nEncountered {} errors.\nSeconds sleeping: {:.2}",
               self.completed_counter, mode, seconds, iter_per_sec, mode, self.bytes_in, self.bytes_out,
               self.bytes_in as f32 / 1024f32, self.bytes_out as f32 / 1024f32,
               self.bytes_in as f32 / 1024f32 / seconds as f32, self.bytes_out as f32 / 1024f32 / seconds as f32,
               self.error_counter, sleep_seconds);
        #[cfg(not(debug_assertions))]
        write!(f, "{} {} in {:.2} seconds\n{:.2} {}/sec\nBytes in/out: {}/{}\nKBytes in/out: {:.2}/{:.2}\nKBytes/sec in/out: {:.2}/{:.2}\nEncountered {} errors.",
               self.completed_counter, mode, seconds, iter_per_sec, mode, self.bytes_in, self.bytes_out,
               self.bytes_in as f32 / 1024f32, self.bytes_out as f32 / 1024f32,
               self.bytes_in as f32 / 1024f32 / seconds as f32, self.bytes_out as f32 / 1024f32 / seconds as f32,
               self.error_counter)
    }
}

#[cfg_attr(not(target_os = "wasi"), tokio::main)]
#[cfg_attr(target_os = "wasi", tokio::main(flavor = "current_thread"))]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let args = Arc::new(Cli::parse());
    let state = Arc::new(RwLock::new(State::new(&args.what)));
    let state_clone = state.clone();

    // Wake up, Steward!
    test_connections(state.clone(), &args.clone().url, 20).await;

    ctrlc::set_handler(move || {
        println!("\n{}", state_clone.read().unwrap());
        std::process::exit(0x0100);
    })
    .expect("Error setting Ctrl-C handler");

    state.write().unwrap().reset();

    if args.what == What::Both {
        state.write().unwrap().what = What::Connections;
        let mut threads = Vec::new();
        for _ in 0..args.workers {
            let state_clone_again = state.clone();
            let args_clone = args.clone();
            let t = tokio::task::spawn(async move {
                if args_clone.what == What::Connections {
                    test_connections(state_clone_again, &args_clone.clone().url, args_clone.iters)
                        .await
                } else {
                    test_attestations(state_clone_again, &args_clone.clone().url, args_clone.iters)
                        .await
                }
            });
            threads.push(t);
        }

        for thread in threads {
            thread.await.unwrap();
        }

        println!("\n{}\n", state.read().unwrap());
        // threads.clear(); // borrower checker very angry here!
        let mut threads = Vec::new();
        state.write().unwrap().reset();

        state.write().unwrap().what = What::Crypto;
        for _ in 0..args.workers {
            let state_clone_again = state.clone();
            let args_clone = args.clone();
            let t = tokio::task::spawn(async move {
                if args_clone.what == What::Connections {
                    test_connections(state_clone_again, &args_clone.clone().url, args_clone.iters)
                        .await
                } else {
                    test_attestations(state_clone_again, &args_clone.clone().url, args_clone.iters)
                        .await
                }
            });
            threads.push(t);
        }

        for thread in threads {
            thread.await.unwrap();
        }
        println!("\n{}", state.read().unwrap());
    } else {
        let mut threads = Vec::new();
        for _ in 0..args.workers {
            let state_clone_again = state.clone();
            let args_clone = args.clone();
            let t = tokio::task::spawn(async move {
                if args_clone.what == What::Connections {
                    test_connections(state_clone_again, &args_clone.clone().url, args_clone.iters)
                        .await
                } else {
                    test_attestations(state_clone_again, &args_clone.clone().url, args_clone.iters)
                        .await
                }
            });
            threads.push(t);
        }

        for thread in threads {
            thread.await.unwrap();
        }
        println!("\n{}", state.read().unwrap());
    }
    Ok(())
}

async fn test_connections(state: Arc<RwLock<State>>, url: &str, iters: u32) {
    let client = Client::new();
    for _iteration in 0..iters {
        let response = client.get(Uri::from_str(url).unwrap()).await.unwrap();

        // Rough, back-of-the-envelop calculations
        match state.write() {
            Ok(mut s) => {
                s.add_bytes(70u64, "GET /".len() as u64);
                if response.status() != StatusCode::OK {
                    s.inc_error();
                } else {
                    s.inc_completed();
                }
                s.sleep();
            }
            Err(e) => {
                eprintln!("Lock error: {e}");
                return;
            }
        }
    }
}

async fn test_attestations(state: Arc<RwLock<State>>, url: &str, iters: u32) {
    let evidence = snp::Evidence {
        vcek: Certificate::from_der(include_bytes!("../../attestation/src/snp/milan.vcek"))
            .unwrap(),
        report: include_bytes!("../../attestation/src/snp/milan.rprt"),
    }
    .to_vec()
    .unwrap();

    let client = Client::new();

    for _iteration in 0..iters {
        let ext = Extension {
            extn_id: OID,
            critical: false,
            extn_value: &evidence,
        };

        let request = Request::builder()
            .method("POST")
            .uri(url)
            .header(CONTENT_TYPE, PKCS10)
            .body(Body::from(cr(SECP_384_R_1, vec![ext])))
            .unwrap();
        let response = client.request(request).await.unwrap();
        let body = <&hyper::Body>::clone(&response.body());
        let bytes_out = body
            .size_hint()
            .exact()
            .unwrap_or_else(|| body.size_hint().lower());
        let mut error_state = response.status() != StatusCode::OK;
        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        error_state = error_state || body.is_empty();

        match state.write() {
            Ok(mut s) => {
                s.add_bytes(body.len() as u64, bytes_out);
                if error_state {
                    s.inc_error();
                } else {
                    s.inc_completed();
                }
                s.sleep();
            }
            Err(e) => {
                eprintln!("Lock error: {e}");
                return;
            }
        }
    }
}

fn cr(curve: ObjectIdentifier, exts: Vec<Extension<'_>>) -> Vec<u8> {
    let pki = PrivateKeyInfo::generate(curve).unwrap();
    let pki = PrivateKeyInfo::from_der(pki.as_ref()).unwrap();
    let spki = pki.public_key().unwrap();

    let req = ExtensionReq::from(exts).to_vec().unwrap();
    let any = AnyRef::from_der(&req).unwrap();
    let att = Attribute {
        oid: ID_EXTENSION_REQ,
        values: vec![any].try_into().unwrap(),
    };

    // Create a certification request information structure.
    let cri = CertReqInfo {
        version: x509::request::Version::V1,
        attributes: vec![att].try_into().unwrap(),
        subject: RdnSequence::default(),
        public_key: spki,
    };

    // Sign the request.
    cri.sign(&pki).unwrap()
}
