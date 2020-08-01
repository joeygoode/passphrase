#![feature(proc_macro_hygiene, decl_macro)]

use serde::{Serialize, Deserialize};
#[macro_use] extern crate rocket;
use rusqlite::{params, Connection};
use rocket_contrib::json::Json;
use rocket::State;
use rocket::response;
use std::sync::{Arc, Mutex};

#[derive(Debug)]
enum Error {
    RusqliteErr(rusqlite::Error),
    SerdeJSONErr(serde_json::Error),
    ApplicationErr(String),
}

enum GetResponse<'r, R: response::Responder<'r>> {
    Ok(R, std::marker::PhantomData<&'r R>),
    NotFound(),
}

impl<'r, R: response::Responder<'r>> response::Responder<'r> for GetResponse<'r, R> {
    fn respond_to(self, req: &rocket::request::Request) -> response::Result<'r> {
        match self {
            GetResponse::Ok(r, _) => r.respond_to(req),
            GetResponse::NotFound() => response::Response::build()
                .status(rocket::http::Status::NotFound)
                .ok(),
        }
    }
}


enum PutResponse<'r> {
    Created(CreatedResponse<'r>),
    NoContent(),
}

impl<'r> response::Responder<'r> for PutResponse<'r> {
    fn respond_to(self, req: &rocket::request::Request) -> response::Result<'r> {
        match self {
            PutResponse::Created(r) => response::ResponseBuilder::new(r.respond_to(req)?)
                .status(rocket::http::Status::Created)
                .ok(),
            PutResponse::NoContent() => response::Response::build()
            .status(rocket::http::Status::NoContent)
            .ok(),
        }
    }
}

struct CreatedResponse<'r> {
    location: rocket::http::uri::Origin<'r>
}

impl<'r> response::Responder<'r> for CreatedResponse<'r> {
    fn respond_to(self, _req: &rocket::request::Request) -> response::Result<'r> {
        response::Response::build()
            .raw_header("Content-Location", self.location.to_string())
            .ok()
    }
}

enum DeleteResponse {
    NoContent(),
    NotFound(),
}

impl<'r> response::Responder<'r> for DeleteResponse {
    fn respond_to(self, _req: &rocket::request::Request) -> response::Result<'r> {
        match self {
            DeleteResponse::NoContent() => response::Response::build()
                .status(rocket::http::Status::NoContent)
                .ok(),
            DeleteResponse::NotFound() => response::Response::build()
                .status(rocket::http::Status::NotFound)
                .ok(),
        }
    }
}

impl From<rusqlite::Error> for Error {
    fn from(e: rusqlite::Error) -> Error {
        Error::RusqliteErr(e)
    }
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Error {
        Error::SerdeJSONErr(e)
    }
}

#[get("/")]
fn index() -> &'static str {
    "Hello, world!"
}

#[get("/sites")]
fn sites(state_db: State<DB>) -> Result<Json<Vec<String>>, Error> {
    let db = state_db.0.lock().unwrap();
    let mut stmt = db.prepare("SELECT site FROM logins")?;
    let site_iter = stmt.query_map(params![], |row| row.get(0))?;
    let mut sites = Vec::new();
    for site_result in site_iter {
        sites.push(site_result?);
    }
    Ok(Json(sites))
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct Details {
    length: Option<i32>,
    forbidden_characters: Vec<String>,
    username: String,
}

#[get("/sites/<site>")]
fn details_for_site(state_db: State<DB>, site: String) -> Result<GetResponse<Json<Vec<Details>>>, Error> {
    let db = state_db.0.lock().unwrap();
    let mut stmt = db.prepare("SELECT username, length, json_group_array(forbidden)
                               FROM logins
                               LEFT JOIN forbidden_characters
                               ON forbidden_characters.site = logins.site
                               WHERE logins.site = ?
                               GROUP BY username, length")?;
    #[derive(Serialize, Deserialize, Debug, Clone)]
    struct Intermediary {
        length: Option<i32>,
        forbidden_characters: String,
        username: String
    }
    let details_iter = stmt.query_map(params![site], |row| {
        Ok(Intermediary{
            username: row.get(0)?,
            length: row.get(1)?,
            forbidden_characters: row.get(2)?,
        })
    })?;
    let mut results = Vec::new();
    for detail_raw in details_iter {
        let detail = detail_raw?;
        let maybe_chars: Vec<Option<String>> = serde_json::from_str(&detail.forbidden_characters)?;
        results.push(Details{
            length: detail.length,
            forbidden_characters: maybe_chars.into_iter().flatten().collect(),
            username: detail.username
        });
    }
    if results.len() == 0 {
        Ok(GetResponse::NotFound())
    } else {
        Ok(GetResponse::Ok(Json(results), std::marker::PhantomData))
    }
}

#[put("/sites/<site>", data = "<input>")]
fn put_site(state_db: State<DB>, site: String, input: Json<Details>) -> Result<PutResponse, Error> {
    let mut db = state_db.0.lock().unwrap();
    let tx = db.transaction()?;
    let mut existing_record: bool = false;
    {
        let mut existing_record_query = tx.prepare("SELECT site FROM logins WHERE site = ?")?;
        let records_iter = existing_record_query.query_map(params![site], |row| row.get(0))?;
        let mut sites: Vec<String> = Vec::new();
        for record in records_iter {
            sites.push(record?);
            existing_record = true;
        }
        let mut replace_login = tx.prepare("REPLACE INTO logins(site, username, length)
                                            VALUES(?, ?, ?)")?;
        let mut delete_forbidden_characters = tx.prepare("DELETE FROM forbidden_characters WHERE site = ?")?;
        let mut insert_forbidden_characters = tx.prepare("INSERT INTO forbidden_characters(site, forbidden)
                                                          VALUES (?, ?)")?;

        let rows_updated = replace_login.execute(params![site, input.0.username, input.0.length])?;
        if rows_updated > 1 {
            return Err(Error::ApplicationErr(format!("updated too many rows: {}", rows_updated)))
        }
        delete_forbidden_characters.execute(params![site])?;
        for character in input.0.forbidden_characters.iter() {
            insert_forbidden_characters.execute(params![site, character])?;
        }
    }
    tx.commit()?;
    if existing_record {
        Ok(PutResponse::NoContent())
    } else {
        Ok(PutResponse::Created(CreatedResponse{location: uri!(details_for_site: site)}))
    }
}

#[delete("/sites/<site>")]
fn delete_site(state_db: State<DB>, site: String) -> Result<DeleteResponse, Error> {
    let mut db = state_db.0.lock().unwrap();
    let tx = db.transaction()?;
    {
        let mut delete_forbidden_characters = tx.prepare("DELETE FROM forbidden_characters WHERE site = ?")?;
        let mut delete_login = tx.prepare("DELETE FROM logins where site = ?")?;

        delete_forbidden_characters.execute(params![site])?;
        let rows_updated = delete_login.execute(params![site])?;
        if rows_updated > 1 {
            return Err(Error::ApplicationErr(format!("deleted too many records for site ({}): {}", site, rows_updated)))
        }
        if rows_updated < 1 {
            return Ok(DeleteResponse::NotFound())
        }
    }
    tx.commit()?;
    Ok(DeleteResponse::NoContent())
}

#[derive(Debug)]
struct Login {
    site: String,
    username: String,
    length: Option<i32>,
}

struct DB(Arc<Mutex<Connection>>);

fn make_db() -> Result<DB, Error> {
    let conn = Connection::open("/home/joey/.passphrase")?;
    Ok(DB(Arc::new(Mutex::new(conn))))
}

fn main() -> Result<(), Error> {
    let db = make_db()?;

    rocket::ignite().manage(db)
        .mount("/", routes![index, sites, details_for_site, put_site, delete_site])
        .launch();
    Ok(())
}
