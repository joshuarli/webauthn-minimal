use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tiny_http::{Header, Method, Response, Server};
use uuid::Uuid;
use webauthn_minimal::{AuthChallenge, RegChallenge, RelyingParty, StoredCredential};

static AUTH_HTML: &str = include_str!("static/auth.html");
static AUTH_JS: &str = include_str!("static/auth.js");

struct Db {
    users: HashMap<String, String>,
    credentials: HashMap<String, Vec<StoredCredential>>,
    sessions: HashMap<String, (Option<String>, String)>,
}

struct AppState {
    db: Mutex<Db>,
    webauthn: RelyingParty,
}

fn json(status: u16, body: impl serde::Serialize) -> Response<std::io::Cursor<Vec<u8>>> {
    let s = serde_json::to_string(&body).unwrap();
    Response::from_string(s)
        .with_status_code(status)
        .with_header(Header::from_bytes(b"Content-Type", b"application/json").unwrap())
}

fn html(body: &str) -> Response<std::io::Cursor<Vec<u8>>> {
    Response::from_string(body)
        .with_header(Header::from_bytes(b"Content-Type", b"text/html").unwrap())
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
            (&Method::Get, "/") | (&Method::Get, "/auth") => html(AUTH_HTML),
            (&Method::Get, "/auth.js") => Response::from_string(AUTH_JS).with_header(
                Header::from_bytes(b"Content-Type", b"application/javascript").unwrap(),
            ),
            (&Method::Post, "/auth/register/options") => {
                let mut body = Vec::new();
                request.as_reader().read_to_end(&mut body).ok();
                let req: serde_json::Value = serde_json::from_slice(&body).unwrap_or_default();
                let username = req["username"].as_str().unwrap_or("");

                if username.is_empty() {
                    json(400, serde_json::json!({"error":"username required"}))
                } else {
                    let user_id = Uuid::new_v4().to_string();
                    {
                        let mut db = state.db.lock().unwrap();
                        db.users.insert(username.to_string(), user_id.clone());
                    }
                    let (options, reg_state) =
                        state.webauthn.start_registration(&user_id, username);
                    let session_id = Uuid::new_v4().to_string();
                    {
                        let mut db = state.db.lock().unwrap();
                        db.sessions.insert(
                            session_id.clone(),
                            (Some(user_id), serde_json::to_string(&reg_state).unwrap()),
                        );
                    }
                    json(
                        200,
                        serde_json::json!({ "session_id": session_id, "options": options }),
                    )
                }
            }
            (&Method::Post, "/auth/register/verify") => {
                let mut body = Vec::new();
                request.as_reader().read_to_end(&mut body).ok();
                let req: serde_json::Value = serde_json::from_slice(&body).unwrap_or_default();
                let session_id = req["session_id"].as_str().unwrap_or("");

                let res = {
                    let db = state.db.lock().unwrap();
                    db.sessions.get(session_id).cloned()
                };

                if let Some((Some(uid), ch)) = res {
                    let reg_state: RegChallenge = serde_json::from_str(&ch).unwrap();
                    match state
                        .webauthn
                        .finish_registration(&req["credential"], &reg_state)
                    {
                        Ok(cred) => {
                            {
                                let mut db = state.db.lock().unwrap();
                                db.credentials.entry(uid.clone()).or_default().push(cred);
                                db.sessions.remove(session_id);
                            }
                            json(200, serde_json::json!({"token":"demo-token-123"}))
                        }
                        Err(e) => json(400, serde_json::json!({"error": e.to_string()})),
                    }
                } else {
                    json(400, serde_json::json!({"error":"invalid session"}))
                }
            }
            (&Method::Post, "/auth/authenticate/options") => {
                let (user_id, creds) = {
                    let db = state.db.lock().unwrap();
                    let uid = db.users.values().next().cloned().unwrap_or_default();
                    let creds = db.credentials.get(&uid).cloned().unwrap_or_default();
                    (uid, creds)
                };
                if creds.is_empty() {
                    json(404, serde_json::json!({"error":"no user registered"}))
                } else {
                    let (options, auth_state) = state.webauthn.start_authentication(&creds);
                    let session_id = Uuid::new_v4().to_string();
                    {
                        let mut db = state.db.lock().unwrap();
                        db.sessions.insert(
                            session_id.clone(),
                            (Some(user_id), serde_json::to_string(&auth_state).unwrap()),
                        );
                    }
                    json(
                        200,
                        serde_json::json!({ "session_id": session_id, "options": options }),
                    )
                }
            }
            (&Method::Post, "/auth/authenticate/verify") => {
                let mut body = Vec::new();
                request.as_reader().read_to_end(&mut body).ok();
                let req: serde_json::Value = serde_json::from_slice(&body).unwrap_or_default();
                let session_id = req["session_id"].as_str().unwrap_or("");

                let res = {
                    let db = state.db.lock().unwrap();
                    db.sessions.get(session_id).cloned()
                };

                if let Some((Some(uid), ch)) = res {
                    let auth_state: AuthChallenge = serde_json::from_str(&ch).unwrap();
                    let creds = {
                        let db = state.db.lock().unwrap();
                        db.credentials.get(&uid).cloned().unwrap_or_default()
                    };
                    match state.webauthn.finish_authentication(
                        &req["credential"],
                        &auth_state,
                        &creds,
                    ) {
                        Ok(_) => {
                            {
                                let mut db = state.db.lock().unwrap();
                                db.sessions.remove(session_id);
                            }
                            json(200, serde_json::json!({"token":"demo-token-123"}))
                        }
                        Err(e) => json(401, serde_json::json!({"error": e.to_string()})),
                    }
                } else {
                    json(400, serde_json::json!({"error":"invalid session"}))
                }
            }
            _ => Response::from_string("Not Found").with_status_code(404),
        };

        let _ = request.respond(response);
    }
}
