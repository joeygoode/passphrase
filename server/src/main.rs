#![feature(proc_macro_hygiene, decl_macro)]

use serde::{Serialize, Deserialize};
use serde_json::value::Value;
#[macro_use] extern crate rocket;
use rusqlite::{params, Connection, Result, Error};
use rocket_contrib::json::Json;
use rocket::State;
use std::sync::{Arc, Mutex};
#[get("/")]
fn index() -> &'static str {
    "Hello, world!"
}

#[get("/sites")]
fn sites(state_db: State<DB>) -> Result<Json<Vec<String>>> {
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
    forbidden_characters: Value,
    username: String,
}

#[get("/sites/<site>")]
fn details_for_site(state_db: State<DB>, site: String) -> Result<Json<Vec<Details>>> {
    let db = state_db.0.lock().unwrap();
    let mut stmt = db.prepare("SELECT username, length, json_group_array(forbidden)
                               FROM logins
                               LEFT JOIN forbidden_characters
                               ON forbidden_characters.site = logins.site
                               WHERE logins.site = ?
                               GROUP BY username, length")?;
    let details_iter = stmt.query_map(params![site], |row| {
        Ok(Details{
            username: row.get(0)?,
            length: row.get(1)?,
            forbidden_characters: row.get(2)?,
        })
    })?;
    let mut results = Vec::new();
    let doctor_results = |d: Details| {
        let forbidden_characters = d.forbidden_characters.clone();
        match forbidden_characters {
            Value::Array(a) => {
                if a.len() == 1 {
                    match a[0] {
                        Value::Null => {
                            let mut cp = d.clone();
                            cp.forbidden_characters = Value::Null;
                            cp
                        }
                        _ => d
                    }
                } else {
                    d
                }
            }
            _ => panic!(format!("Expected an array but got {}", d.forbidden_characters))
        }
    };
    for detail_raw in details_iter {
        results.push(doctor_results(detail_raw?));
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

fn main() -> Result<()> {
    let db = make_db()?;

    rocket::ignite().manage(db)
        .mount("/", routes![index, sites, details_for_site])
        .launch();
    Ok(())
}
