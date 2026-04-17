//! Authoritative DNS server for `mlsh.io`.
//!
//! Inspired by [calaos_dns](https://github.com/calaos/calaos_dns): the zone
//! data lives in SQLite (`ingress_routes` + `dns_txt_records`), and the DNS
//! server answers UDP/TCP queries on :53 directly from that source.
//!
//! Answers:
//! - Wildcard A record for `*.mlsh.io`: direct-mode domain → node IP,
//!   everything else → `config.dns_public_ip` (the outer SNI proxy's IP).
//! - TXT records for `_acme-challenge.<domain>` from `dns_txt_records`.
//! - SOA and NS for the apex.
//!
//! The ACME DNS-01 validator follows CNAMEs etc; this server keeps things
//! flat. That's sufficient for in-zone wildcard challenges served alongside
//! the A records.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use async_trait::async_trait;
use hickory_proto::op::{Header, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::rdata::{NS, SOA, TXT};
use hickory_proto::rr::{LowerName, Name, RData, Record, RecordType};
use hickory_server::authority::MessageResponseBuilder;
use hickory_server::server::{Request, RequestHandler, ResponseHandler, ResponseInfo, ServerFuture};
use sqlx::SqlitePool;
use tokio::net::{TcpListener, UdpSocket};
use tracing::{debug, info, warn};

use crate::config::Config;
use crate::db;

const TTL_APEX: u32 = 3600;
const TTL_WILDCARD: u32 = 300;
const TTL_TXT: u32 = 60;
const TCP_IDLE: Duration = Duration::from_secs(5);

/// Run the authoritative DNS server until `shutdown` fires.
pub async fn run(
    bind_addr: SocketAddr,
    pool: SqlitePool,
    config: Arc<Config>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) -> Result<()> {
    let handler = MlshHandler { pool, config };

    let udp = UdpSocket::bind(bind_addr)
        .await
        .with_context(|| format!("Failed to bind DNS UDP on {}", bind_addr))?;
    let tcp = TcpListener::bind(bind_addr)
        .await
        .with_context(|| format!("Failed to bind DNS TCP on {}", bind_addr))?;

    info!("Authoritative DNS listening on {} (UDP+TCP)", bind_addr);

    let mut server = ServerFuture::new(handler);
    server.register_socket(udp);
    server.register_listener(tcp, TCP_IDLE);

    tokio::select! {
        r = server.block_until_done() => {
            if let Err(e) = r {
                warn!("DNS server terminated: {}", e);
            }
        }
        _ = shutdown.changed() => {
            info!("DNS server shutting down");
        }
    }
    Ok(())
}

// -------------------------------------------------------------------------
// Request handler
// -------------------------------------------------------------------------

#[derive(Clone)]
struct MlshHandler {
    pool: SqlitePool,
    config: Arc<Config>,
}

impl MlshHandler {
    fn zone_name(&self) -> Name {
        Name::from_ascii(&self.config.dns_zone)
            .unwrap_or_else(|_| Name::from_ascii("mlsh.io.").unwrap())
    }

    fn ns_name(&self) -> Name {
        Name::from_ascii(&self.config.dns_soa_mname).unwrap_or_else(|_| self.zone_name())
    }

    fn apex_ip(&self) -> Option<Ipv4Addr> {
        self.config.dns_public_ip.parse::<Ipv4Addr>().ok()
    }
}

#[async_trait]
impl RequestHandler for MlshHandler {
    async fn handle_request<R: ResponseHandler>(
        &self,
        request: &Request,
        mut response_handle: R,
    ) -> ResponseInfo {
        let mut header = Header::response_from_request(request.header());
        header.set_message_type(MessageType::Response);
        header.set_authoritative(true);

        // Reject non-query opcodes / non-IN class.
        if request.op_code() != OpCode::Query {
            return reply_error(&mut response_handle, request, header, ResponseCode::NotImp).await;
        }

        let info = match request.request_info() {
            Ok(i) => i,
            Err(_) => {
                return reply_error(
                    &mut response_handle,
                    request,
                    header,
                    ResponseCode::FormErr,
                )
                .await
            }
        };
        let qtype = info.query.query_type();
        let qname_lower: LowerName = info.query.name().clone();
        let qname: Name = qname_lower.into();

        let zone = self.zone_name();
        if !qname.zone_of(&qname) || !zone_contains(&zone, &qname) {
            // Not authoritative for this name.
            return reply_error(&mut response_handle, request, header, ResponseCode::Refused).await;
        }

        let mut answers: Vec<Record> = Vec::new();
        let mut authorities: Vec<Record> = Vec::new();

        match qtype {
            RecordType::A => {
                if let Some(ip) = self.resolve_a(&qname).await {
                    answers.push(Record::from_rdata(
                        qname.clone(),
                        ttl_for(&qname, &zone),
                        RData::A(ip.into()),
                    ));
                } else {
                    authorities.push(self.soa_record());
                    header.set_response_code(ResponseCode::NXDomain);
                }
            }
            RecordType::TXT => {
                let txts = match db::list_dns_txt(&self.pool).await {
                    Ok(v) => v,
                    Err(e) => {
                        warn!(error = %e, "DB error loading TXT records");
                        Vec::new()
                    }
                };
                let want = qname.to_ascii().trim_end_matches('.').to_ascii_lowercase();
                for (name, value) in &txts {
                    if name.eq_ignore_ascii_case(&want) {
                        answers.push(Record::from_rdata(
                            qname.clone(),
                            TTL_TXT,
                            RData::TXT(TXT::new(vec![value.clone()])),
                        ));
                    }
                }
                if answers.is_empty() {
                    authorities.push(self.soa_record());
                }
            }
            RecordType::SOA => {
                if qname == zone {
                    answers.push(self.soa_record());
                }
            }
            RecordType::NS => {
                if qname == zone {
                    answers.push(Record::from_rdata(
                        zone.clone(),
                        TTL_APEX,
                        RData::NS(NS(self.ns_name())),
                    ));
                }
            }
            _ => {
                // Non-A/TXT/SOA/NS: no data.
                authorities.push(self.soa_record());
            }
        }

        debug!(
            ?qname,
            ?qtype,
            answers = answers.len(),
            "DNS response"
        );

        let builder = MessageResponseBuilder::from_message_request(request);
        let msg = builder.build(
            header,
            answers.iter(),
            authorities.iter(),
            std::iter::empty(),
            std::iter::empty(),
        );

        match response_handle.send_response(msg).await {
            Ok(info) => info,
            Err(e) => {
                warn!(error = %e, "DNS send_response failed");
                let mut h = Header::new();
                h.set_id(request.id());
                h.set_response_code(ResponseCode::ServFail);
                h.into()
            }
        }
    }
}

impl MlshHandler {
    async fn resolve_a(&self, qname: &Name) -> Option<Ipv4Addr> {
        let zone = self.zone_name();
        // Apex (mlsh.io / ingress.mlsh.io / signal.mlsh.io) → public IP.
        if qname == &zone {
            return self.apex_ip();
        }
        let name = qname.to_ascii().trim_end_matches('.').to_ascii_lowercase();

        // Exact match against registered ingress routes.
        if let Ok(Some(route)) =
            db::lookup_ingress_route_by_domain(&self.pool, &name).await
        {
            if route.public_mode == "direct" {
                if let Ok(ip) = route.public_ip.parse::<Ipv4Addr>() {
                    return Some(ip);
                }
            }
            // Relay mode (or missing direct IP) → fall through to wildcard.
        }

        // Reserved admin hosts + wildcard → public IP.
        self.apex_ip()
    }

    fn soa_record(&self) -> Record {
        let zone = self.zone_name();
        let rdata = SOA::new(
            self.ns_name(),
            Name::from_ascii(&self.config.dns_soa_rname).unwrap_or_else(|_| zone.clone()),
            serial_from_now(),
            3600,
            600,
            604_800,
            60,
        );
        Record::from_rdata(zone, TTL_APEX, RData::SOA(rdata))
    }
}

fn zone_contains(zone: &Name, qname: &Name) -> bool {
    zone.zone_of(qname)
}

fn ttl_for(qname: &Name, zone: &Name) -> u32 {
    if qname == zone {
        TTL_APEX
    } else {
        TTL_WILDCARD
    }
}

fn serial_from_now() -> u32 {
    // YYYYMMDDNN-ish. Use unix time truncated — monotonic enough for our use.
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as u32)
        .unwrap_or(1)
}

async fn reply_error<R: ResponseHandler>(
    response_handle: &mut R,
    request: &Request,
    mut header: Header,
    code: ResponseCode,
) -> ResponseInfo {
    header.set_response_code(code);
    let builder = MessageResponseBuilder::from_message_request(request);
    let msg = builder.build(
        header,
        std::iter::empty(),
        std::iter::empty(),
        std::iter::empty(),
        std::iter::empty(),
    );
    match response_handle.send_response(msg).await {
        Ok(info) => info,
        Err(_) => {
            let mut h = Header::new();
            h.set_id(request.id());
            h.set_response_code(code);
            h.into()
        }
    }
}

// Silence an unused-import warning under certain feature combos.
#[allow(dead_code)]
fn _unused_ip_addr(_: IpAddr) {}
