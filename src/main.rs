use anyhow::Result;
use std::{
    collections::{BTreeMap as Map, BTreeSet as Set},
    io::Write,
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

#[derive(Clone, Debug, Default)]
struct DomainNameservers {
    nameservers: Set<Name>,
}

#[derive(Clone, Debug, Default)]
struct RecordDomains {
    domains: Set<Name>,
}

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

    let mut nameservers: Map<Name, Set<Name>> = Map::new();

    for name in opt.domains {
        let response = client
            .query(name.clone(), DNSClass::IN, RecordType::NS)
            .await?;
        for answers in response.answers() {
            if let RData::NS(ref nameserver) = *answers.rdata() {
                nameservers
                    .entry(nameserver.clone())
                    .or_default()
                    .insert(name.clone());
            }
        }
    }

    let mut domains: Map<Name, DomainNameservers> = Map::new();
    let mut records: Map<RData, RecordDomains> = Map::new();

    for (nameserver, ns_domains) in nameservers.iter() {
        for domain in ns_domains {
            let domain_nameservers = domains.entry(domain.clone()).or_default();
            domain_nameservers.nameservers.insert(nameserver.clone());
        }

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

            for answer in response_a
                .answers()
                .iter()
                .chain(response_aaaa.answers().iter())
            {
                match answer.rdata() {
                    record @ (RData::A(_) | RData::AAAA(_) | RData::CNAME(_)) => {
                        let record = records.entry(record.clone()).or_default();
                        record.domains.insert(domain.clone());
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
        for domain in record_domains.domains.iter() {
            let nameservers = domains.get(domain).unwrap();
            for nameserver in nameservers.nameservers.iter() {
                let (nameserver_count, domains) =
                    common_nameservers.entry(nameserver.clone()).or_default();
                *nameserver_count += 1;
                domains.insert(domain.clone());
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
