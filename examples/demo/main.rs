use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tiny_http::{Server, Response, Method, Header};
use webauthn_minimal::{RelyingParty, RegChallenge, AuthChallenge, StoredCredential};
use uuid::Uuid;

static AUTH_HTML: &str = include_str!("static/auth.html");

struct Db {
    users: HashMap<String, String>,         // username -> user_id
    credentials: HashMap<String, Vec<StoredCredential>>, // user_id -> creds
    sessions: HashMap<String, (Option<String>, String)>, // session_id -> (user_id, challenge_json)
}

struct AppState {
    db: Mutex<Db>,
    webauthn: RelyingParty,
}

fn main() {
    let server = Server::http("0.0.0.0:8080").expect("failed to bind to port 8080");
    println!("Demo server running at http://localhost:8080");

    let state = Arc::new(AppState {
        db: Mutex::new(Db {
            users: HashMap::new(),
            credentials: HashMap::new(),
            sessions: HashMap::new(),
        }),
        webauthn: RelyingParty::new("localhost", "http://localhost:8080", "WebAuthn Demo"),
    });

    for mut request in server.incoming_requests() {
        let state = Arc::clone(&state);
        let url = request.url().to_string();
        let method = request.method();

        let response = match (method, url.as_str()) {
            (&Method::Get, "/") => {
                Response::from_string(AUTH_HTML).with_header(Header::from_bytes(b"Content-Type", b"text/html").unwrap())
            }
            (&Method::Get, "/auth") => {
                Response::from_string(AUTH_HTML).with_header(Header::from_bytes(b"Content-Type", b"text/html").unwrap())
            }
            (&Method::Post, "/auth/register/options") => {
                let mut body = Vec::new();
                request.as_reader().read_to_end(&mut body).ok();

                #[derive(serde::Deserialize)]
                struct Req { username: String }
                let req: Req = serde_json::from_slice(&body).unwrap_or_else(|_| Req { username: "".into() });

                if req.username.is_empty() {
                    Response::from_string(r#"{"error":"username required"}"#).with_header(Header::from_bytes(b"Content-Type", b"application/json").unwrap())
                } else {
                    let user_id = Uuid::new_v4().to_string();
                    {
                        let mut db = state.db.lock().unwrap();
                        db.users.insert(req.username.clone(), user_id.clone());
                    }

                    let (options, reg_state) = state.webauthn.start_registration(&user_id, &req.username);
                    let challenge_json = serde_json::to_string(&reg_state).unwrap();
                    let session_id = Uuid::new_v4().to_string();
                    {
                        let mut db = state.db.lock().unwrap();
                        db.sessions.insert(session_id.clone(), (Some(user_id), challenge_json));
                    }

                    let body = serde_json::json!({ "session_id": session_id, "options": options });
                    Response::from_string(&body.to_string()).with_header(Header::from_bytes(b"Content-Type", b"application/json").unwrap())
                }
            }
            (&Method::Post, "/auth/register/verify") => {
                let mut body = Vec::new();
                request.as_reader().read_to_end(&mut body).ok();

                #[derive(serde::Deserialize)]
                struct Req { session_id: String, credential: serde_json::Value }
                let req: Req = serde_json::from_slice(&body).unwrap_or_else(|_| Req { session_id: "".into(), credential: serde_json::Value::Null });

                let res = {
                    let db = state.db.lock().unwrap();
                    match db.sessions.get(&req.session_id) {
                        Some((Some(uid), ch)) => Some((uid.clone(), ch.clone())),
                        _ => None,
                    }
                };

                if let Some((user_id, challenge_json)) = res {
                    let reg_state: RegChallenge = serde_json::from_str(&challenge_json).unwrap();
                    match state.webauthn.finish_registration(&req.credential, &reg_state) {
                        Ok(cred) => {
                            {
                                let mut db = state.db.lock().unwrap();
                                db.credentials.entry(user_id.clone()).or_default().push(cred);
                                db.sessions.remove(&req.session_id);
                            }
                            Response::from_string(r#"{"token":"demo-token-123"}"#).with_header(Header::from_bytes(b"Content-Type", b"application/json").unwrap())
                        }
                        Err(e) => Response::from_string(&format!(r#"{{"error":"{}"}}"#, e)).with_header(Header::from_bytes(b"Content-Type", b"application/json").unwrap()),
                    }
                } else {
                    Response::from_string(r#"{"error":"invalid session"}"#).with_header(Header::from_bytes(b"Content-Type", b"application/json").unwrap())
                }
            }
            (&Method::Post, "/auth/authenticate/options") => {
                let (user_id, creds) = {
                    let db = state.db.lock().unwrap();
                    let user_id = db.users.values().next().cloned().unwrap_or_default();
                    let creds = db.credentials.get(&user_id).cloned().unwrap_or_default();
                    (user_id, creds)
                };

                if creds.is_empty() {
                    Response::from_string(r#"{"error":"no user registered"}"#).with_status_code(404).with_header(Header::from_bytes(b"Content-Type", b"application/json").unwrap())
                } else {
                    let (options, auth_state) = state.webauthn.start_authentication(&creds);
                    let challenge_json = serde_json::to_string(&auth_state).unwrap();
                    let session_id = Uuid::new_v4().to_string();
                    {
                        let mut db = state.db.lock().unwrap();
                        db.sessions.insert(session_id.clone(), (Some(user_id), challenge_json));
                    }
                    let body = serde_json::json!({ "session_id": session_id, "options": options });
                    Response::from_string(&body.to_string()).with_header(Header::from_bytes(b"Content-Type", b"application/json").unwrap())
                }
            }
            (&Method::Post, "/auth/authenticate/verify") => {
                let mut body = Vec::new();
                request.as_reader().read_to_end(&mut body).ok();

                #[derive(serde::Deserialize)]
                struct Req { session_id: String, credential: serde_json::Value }
                let req: Req = serde_json::from_slice(&body).unwrap_or_else(|_| Req { session_id: "".into(), credential: serde_json::Value::Null });

                let res = {
                    let db = state.db.lock().unwrap();
                    match db.sessions.get(&req.session_id) {
                        Some((Some(uid), ch)) => Some((uid.clone(), ch.clone())),
                        _ => None,
                    }
                };

                if let Some((user_id, challenge_json)) = res {
                    let auth_state: AuthChallenge = serde_json::from_str(&challenge_json).unwrap();
                    let creds = {
                        let db = state.db.lock().unwrap();
                        db.credentials.get(&user_id).cloned().unwrap_or_default()
                    } ;

                    match state.webauthn.finish_authentication(&req.credential, &auth_state, &creds) {
                        Ok(_) => {
                            {
                                let mut db = state.db.lock().unwrap();
                                db.sessions.remove(&req.session_id);
                            }
                            Response::from_string(r#"{"token":"demo-token-123"}"#).with_header(Header::from_bytes(b"Content-Type", b"application/json").unwrap())
                        }
                        Err(e) => Response::from_string(&format!(r#"{{"error":"{}"}}"#, e)).with_header(Header::from_bytes(b"Content-Type", b"application/json").unwrap()),
                    }
                } else {
                    Response::from_string(r#"{"error":"invalid session"}"#).with_header(Header::from_bytes(b"Content-Type", b"application/json").unwrap())
                }
            }
            _ => Response::from_string("Not Found").with_status_code(404),
        };

        let _ = request.respond(response);
    }
}
