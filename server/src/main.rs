#![feature(proc_macro_hygiene, decl_macro)]

use serde::{Serialize, Deserialize};
use serde_json::value::Value;
#[macro_use] extern crate rocket;
use rusqlite::{params, Connection};
use rocket_contrib::json::Json;
use rocket::State;
use std::sync::{Arc, Mutex};

#[derive(Debug)]
enum Error {
    RusqliteErr(rusqlite::Error),
    SerdeJSONErr(serde_json::Error),
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
fn details_for_site(state_db: State<DB>, site: String) -> Result<Json<Vec<Details>>, Error> {
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
        results.push(Details{
            length: detail.length,
            forbidden_characters: serde_json::from_str(&detail.forbidden_characters)?,
            username: detail.username
        });
    }
    Ok(Json(results))
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
        .mount("/", routes![index, sites, details_for_site])
        .launch();
    Ok(())
}
