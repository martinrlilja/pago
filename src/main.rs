use anyhow::Result;
use std::{
    collections::{BTreeMap as Map, BTreeSet as Set},
    io::Write,
    time::Duration,
};
use structopt::StructOpt;
use termion::{color, style};
use tokio::net::UdpSocket;

use trust_dns_client::{
    client::{AsyncClient, ClientHandle},
    rr::{DNSClass, Name, RData, RecordType},
    udp::UdpClientStream,
};

fn parse_name(name: &str) -> Result<Name> {
    Name::from_utf8(name).map_err(Into::into)
}

#[derive(StructOpt, Debug)]
#[structopt(name = "pago")]
struct Opt {
    /// Domains to dig.
    #[structopt(name = "DOMAIN", required = true, parse(try_from_str = parse_name))]
    domains: Vec<Name>,
}

const QUERY_TIMEOUT: Duration = Duration::from_millis(250);

#[tokio::main]
async fn main() -> Result<()> {
    let opt = Opt::from_args();

    let stream = UdpClientStream::<UdpSocket>::new(([8, 8, 8, 8], 53).into());
    let (mut client, bg) = AsyncClient::connect(stream).await?;

    tokio::spawn(async {
        let res = bg.await;
        if let Err(err) = res {
            println!("ERROR: {:?}", err);
        }
    });

    let mut domain_soa: Map<Name, Name> = Map::new();
    let mut domain_soa_queried: Set<Name> = Set::new();
    let mut domains = opt.domains.clone();

    while let Some(name) = domains.pop() {
        if !domain_soa_queried.insert(name.clone()) {
            continue;
        }

        let response = client
            .query(name.clone(), DNSClass::IN, RecordType::SOA)
            .await?;
        tokio::time::sleep(QUERY_TIMEOUT).await;

        for answer in response.answers() {
            if let RData::SOA(ref soa) = *answer.rdata() {
                domain_soa.insert(answer.name().clone(), soa.mname().clone());
            }
        }

        let parent = name.base_name();
        if !parent.is_root() {
            domains.push(parent);
        }
    }

    let mut nameservers: Map<Name, Set<Name>> = Map::new();
    let mut domains: Map<Name, Set<Name>> = Map::new();
    let mut records: Map<RData, Set<Name>> = Map::new();

    for name in opt.domains {
        let response = client
            .query(name.clone(), DNSClass::IN, RecordType::NS)
            .await?;
        tokio::time::sleep(QUERY_TIMEOUT).await;

        for answer in response.answers() {
            match *answer.rdata() {
                RData::CNAME(ref domain) => {
                    domains.entry(answer.name().clone()).or_default();
                    records.entry(RData::CNAME(domain.clone()))
                        .or_default()
                        .insert(answer.name().clone());
                }
                RData::NS(ref nameserver) => {
                    nameservers
                        .entry(nameserver.clone())
                        .or_default()
                        .insert(answer.name().clone());
                    domains.entry(answer.name().clone())
                        .or_default()
                        .insert(nameserver.clone());
                }
                _ => continue,
            }
        }
    }

    for (nameserver, ns_domains) in nameservers.iter() {
        let ns_str = nameserver.to_ascii();
        let addrs = tokio::net::lookup_host((ns_str.as_str(), 53))
            .await?
            .collect::<Vec<_>>();

        if addrs.is_empty() {
            println!("WARN: no address found for nameserver: {}", ns_str);
            continue;
        }

        let &ns_addr = addrs.first().unwrap();
        let stream = UdpClientStream::<UdpSocket>::new(ns_addr);
        let (mut client, bg) = AsyncClient::connect(stream).await?;

        let bg = tokio::spawn(async move {
            let res = bg.await;
            if let Err(err) = res {
                println!("ERROR: ({}) {:?}", ns_str, err);
            }
        });

        for domain in ns_domains {
            let response_a = client
                .query(domain.clone(), DNSClass::IN, RecordType::A)
                .await?;
            let response_aaaa = client
                .query(domain.clone(), DNSClass::IN, RecordType::AAAA)
                .await?;
            let responses = response_a
                .answers()
                .iter()
                .chain(response_aaaa.answers().iter());
            tokio::time::sleep(QUERY_TIMEOUT).await;

            for answer in responses {
                match answer.rdata() {
                    record @ (RData::A(_) | RData::AAAA(_) | RData::CNAME(_)) => {
                        records.entry(record.clone()).or_default().insert(domain.clone());
                    }
                    _ => continue,
                }
            }
        }

        // Stop the background task for this nameserver.
        bg.abort();
    }

    let mut results: Map<(RecordType, Vec<(Set<Name>, Set<Name>)>), Set<RData>> = Map::new();

    for (record, record_domains) in records {
        let record_type = match record {
            RData::A(_) => RecordType::A,
            RData::AAAA(_) => RecordType::AAAA,
            RData::CNAME(_) => RecordType::CNAME,
            _ => continue,
        };

        let mut common_nameservers: Map<Name, (usize, Set<Name>)> = Map::new();
        for domain in record_domains.iter() {
            let nameservers = domains.get(domain).unwrap();
            for nameserver in nameservers {
                let (nameserver_count, domains) =
                    common_nameservers.entry(nameserver.clone()).or_default();
                *nameserver_count += 1;
                domains.insert(domain.clone());
            }

            if nameservers.is_empty() {
                // Our nameservers are somewhere else, so add the SOA as the nameserver.
                let mut base_name = domain.clone();
                while !base_name.is_root() {
                    if let Some(soa) = domain_soa.get(&base_name) {
                        let (nameserver_count, domains) =
                            common_nameservers.entry(soa.clone()).or_default();
                        *nameserver_count += 1;
                        domains.insert(domain.clone());
                        break;
                    }
                    base_name = base_name.base_name();
                }

            }
        }

        let mut common_nameservers_grouped_by_count: Map<(usize, Set<Name>), Set<Name>> =
            Map::new();
        for (nameserver, (count, domains)) in common_nameservers {
            common_nameservers_grouped_by_count
                .entry((count, domains))
                .or_default()
                .insert(nameserver.clone());
        }

        let result = common_nameservers_grouped_by_count
            .into_iter()
            .map(|((_, domains), nameservers)| (domains, nameservers))
            .rev()
            .collect::<Vec<_>>();

        results
            .entry((record_type, result).clone())
            .or_default()
            .insert(record);
    }

    for ((record_type, result), records) in results {
        let initial_indent = match record_type {
            RecordType::A => format!(
                "{}{}    A{}",
                style::Bold,
                color::Fg(color::LightBlue),
                color::Fg(color::Reset),
            ),
            RecordType::AAAA => format!(
                "{}{} AAAA{}",
                style::Bold,
                color::Fg(color::LightMagenta),
                color::Fg(color::Reset),
            ),
            RecordType::CNAME => format!(
                "{}{}CNAME{}",
                style::Bold,
                color::Fg(color::LightYellow),
                color::Fg(color::Reset),
            ),
            other => unreachable!("unexpected record type {}", other),
        };

        let textwrap = textwrap::Options::with_termwidth()
            .initial_indent(&initial_indent)
            .subsequent_indent("      ")
            .word_splitter(textwrap::word_splitters::NoHyphenation);

        let mut record_str = Vec::new();
        for record in records {
            match record {
                RData::A(ip) => write!(&mut record_str, " {}", ip)?,
                RData::AAAA(ip) => write!(&mut record_str, " {}", ip)?,
                RData::CNAME(name) => write!(&mut record_str, " {}", name)?,
                data => unreachable!("unexpected record data {}", data),
            }
        }

        let record_str = String::from_utf8(record_str)?;
        println!("{}{}", textwrap::fill(&record_str, textwrap), style::Reset);

        for (domains, nameservers) in result {
            let mut domain_str = Vec::new();
            for domain in domains {
                write!(&mut domain_str, " {}", domain)?;
            }

            let domain_str = String::from_utf8(domain_str)?;
            let initial_indent = format!(
                "      {}{}Domains:{}",
                style::Bold,
                color::Fg(color::LightCyan),
                color::Fg(color::Reset)
            );
            let textwrap = textwrap::Options::with_termwidth()
                .initial_indent(&initial_indent)
                .subsequent_indent("              ")
                .word_splitter(textwrap::word_splitters::NoHyphenation);
            println!("{}{}", textwrap::fill(&domain_str, textwrap), style::Reset);

            let initial_indent = format!(
                "      {}Nameservers:{}",
                color::Fg(color::LightCyan),
                style::Reset,
            );
            let textwrap = textwrap::Options::with_termwidth()
                .initial_indent(&initial_indent)
                .subsequent_indent("                   ")
                .word_splitter(textwrap::word_splitters::NoHyphenation);

            let mut nameservers_str = Vec::new();
            for nameserver in nameservers {
                write!(&mut nameservers_str, " {}", nameserver)?;
            }

            let nameservers_str = String::from_utf8(nameservers_str)?;
            println!(
                "{}{}",
                textwrap::fill(&nameservers_str, textwrap),
                style::Reset
            );
        }
    }

    Ok(())
}
