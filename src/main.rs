use std::{
    fs::File,
    io::Write,
    path::Path,
    process::{Command, Stdio},
    str::from_utf8,
};

use clap::{crate_authors, crate_version, App, Arg, ArgMatches};
use curl::easy::Easy;
use regex::Regex;

struct QueryData {
    query: String,
    country: String,
    isp: String,
    asvalue: String,
    asname: String,
}

fn main() {
    if cfg!(windows) {
        panic!("UNIX Only!");
    }
    let output_path = Path::new("output.txt");

    let traceroot_name = "traceroute";
    let args = parse_args();
    let addr = args.value_of("ADDRESS").unwrap();
    let ttl = args.value_of("ttl").unwrap();

    let traceroot_process = Command::new(traceroot_name)
        .arg(addr)
        .arg(format!("-m {}", ttl).as_str())
        .stdout(Stdio::piped())
        .spawn()
        .expect(format!("Failed to run {} with address {}", traceroot_name, addr).as_str());
    let traceroot_output = traceroot_process.wait_with_output().unwrap();

    let converted_result = from_utf8(traceroot_output.stdout.as_slice()).unwrap();
    let regex = Regex::new(r#"\(([\d.]*)\)"#).unwrap();
    let queries = regex
        .captures_iter(converted_result)
        .map(|caps| caps.get(1).unwrap().as_str())
        .skip(3)
        .collect::<Vec<&str>>();

    let mut queries_parsed: Vec<QueryData> = Vec::new();
    let mut buf = Vec::new();
    for query in &queries {
        println!("{}", query);
        let mut curl_handle = Easy::new();
        curl_handle
            .url(format!(r#"http://ip-api.com/json/{}?fields=4255743"#, query).as_str())
            .expect("Error getting ip-api.com url");
        let mut transfer = curl_handle.transfer();
        transfer
            .write_function(|responce| {
                let decoded = from_utf8(responce).unwrap().to_owned();
                buf.push(decoded);
                Ok(responce.len())
            })
            .unwrap();
        transfer.perform().unwrap();
    }

    for json_string in buf {
        let resp_json = json::parse(json_string.as_str()).unwrap();

        if resp_json["status"] == "success" {
            queries_parsed.push(QueryData {
                query: resp_json["query"].to_string(),
                country: resp_json["country"].to_string(),
                isp: resp_json["isp"].to_string(),
                asvalue: resp_json["as"].to_string(),
                asname: resp_json["asname"].to_string(),
            });
        }
    }

    let mut output_vec = Vec::new();
    output_vec.push(format!(
        "{0: >2}. | {1: <16} | {2: <16} | {3: <50} | {4: <30} | {5: <20}",
        "№", "Query", "Country", "ISP", "AS", "AS-Name",
    ));
    queries_parsed.iter().enumerate().for_each(|(num, query)| {
        output_vec.push(format!(
            "{0: >2}. | {1: <16} | {2: <16} | {3: <50} | {4: <30} | {5: <20}",
            &num, query.query, query.country, query.isp, query.asvalue, query.asname,
        ))
    });

    let output_string = output_vec.join("\n");
    let mut output_file = File::create(output_path).unwrap();
    output_file.write_all(output_string.as_bytes()).unwrap();

    println!("{}", output_string);
}

fn parse_args() -> ArgMatches<'static> {
    App::new("Traceroute Queries Parser")
        .setting(clap::AppSettings::ArgRequiredElseHelp)
        .version(crate_version!())
        .author(crate_authors!())
        .about("AS Tracerouting App")
        .arg(
            Arg::with_name("ADDRESS")
                .help("Trace route to provided ADDRESS")
                .required(true)
                .index(1),
        )
        .arg(
            Arg::with_name("ttl")
                .help("Max TTL / Hops")
                .default_value("15")
                .short("t")
                .long("ttl"),
        )
        .get_matches()
}
