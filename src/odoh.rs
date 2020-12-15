use anyhow::{anyhow, Context, Result};
use odoh_rs::protocol::{
    create_query_msg, get_supported_config, parse_received_response, ObliviousDoHConfigContents,
    ObliviousDoHQueryBody, ODOH_HTTP_HEADER,
};
use reqwest::{
    header::{HeaderMap, ACCEPT, CACHE_CONTROL, CONTENT_TYPE},
    Client, StatusCode,
};
use trust_dns_proto::op::Message;
use url::Url;

use crate::dns_utils::{create_dns_query, fetch_odoh_config, parse_dns_answer};

const QUERY_PATH: &str = "/dns-query";

#[derive(Clone, Debug)]
pub struct ODOHSession {
    pub target: Url,
    pub proxy: Option<Url>,
    pub target_config: ObliviousDoHConfigContents,
    pub client: Client,
}

pub struct ODOHRequest {
    pub query: ObliviousDoHQueryBody,
    pub client_secret: Vec<u8>,
    pub encrypted_query: Vec<u8>,
}

pub struct ODOHResponse {
    pub request: ODOHRequest,
    pub encrypted_response: Vec<u8>,
}

impl ODOHSession {
    /// Create a new ClientSession
    pub async fn new(target: &str, proxy: Option<&str>) -> Result<Self> {
        let mut target_url = Url::parse(target)?;
        target_url.set_path(QUERY_PATH);
        let proxy = if let Some(p) = proxy {
            Url::parse(p).ok()
        } else {
            None
        };
        let odoh_config = fetch_odoh_config(target).await?;
        let target_config = get_supported_config(&odoh_config)?;
        Ok(Self {
            target: target_url,
            proxy,
            target_config,
            client: Client::new(),
        })
    }

    /// Create an oblivious query from a domain and query type
    pub fn create_request(&self, domain: &str, qtype: &str) -> Result<ODOHRequest> {
        // create a DNS message
        let dns_msg = create_dns_query(domain, qtype)?;
        let query = ObliviousDoHQueryBody::new(&dns_msg, Some(1));
        let (encrypted_query, client_secret) = create_query_msg(&self.target_config, &query)?;
        Ok(ODOHRequest {
            query,
            client_secret,
            encrypted_query,
        })
    }

    /// Set headers and build an HTTP request to send the oblivious query to
    /// the proxy/target.
    /// If a proxy is specified, the request will be sent to the proxy.
    /// However, if a proxy is absent,
    /// it will be sent directly to the target. Note that not specifying
    /// a proxy effectively nullifies
    /// the entire purpose of using ODoH.
    pub async fn send_request(&self, request: ODOHRequest) -> Result<ODOHResponse> {
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, ODOH_HTTP_HEADER.parse()?);
        headers.insert(ACCEPT, ODOH_HTTP_HEADER.parse()?);
        headers.insert(CACHE_CONTROL, "no-cache, no-store".parse()?);
        let query = [
            (
                "targethost",
                self.target
                    .host_str()
                    .context("Target host is not a valid host string")?,
            ),
            ("targetpath", QUERY_PATH),
        ];

        let builder = if let Some(p) = &self.proxy {
            self.client.post(p.clone()).headers(headers).query(&query)
        } else {
            self.client.post(self.target.clone()).headers(headers)
        };
        let send = builder.body(request.encrypted_query.clone()).send();

        let resp = send.await?;
        if resp.status() != StatusCode::OK {
            return Err(anyhow!(
                "query failed with response status code {}",
                resp.status().as_u16()
            ));
        }
        let bytes = resp.bytes();

        Ok(ODOHResponse {
            request,
            encrypted_response: bytes.await?.to_vec(),
        })
    }

    /// Parse the received response from the resolver and print the answer.
    pub fn parse_response(&self, resp: ODOHResponse) -> Result<Message> {
        let response_body = parse_received_response(
            &resp.request.client_secret.clone(),
            &resp.encrypted_response,
            &resp.request.query.clone(),
        )?;
        Ok(parse_dns_answer(&response_body.dns_msg)?)
    }

    pub async fn resolve(&self, domain: &str, qtype: &str) -> Result<Message> {
        let request = self.create_request(domain, qtype)?;
        let response = self.send_request(request).await?;
        let dns_message = self.parse_response(response)?;
        Ok(dns_message)
    }
}
