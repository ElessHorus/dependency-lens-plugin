//! HTTP transport seam: the host implementation and a test double.

use openidea_plugin::{HttpRequest, HttpResponse, host};
use std::borrow::Cow;

/// Timeout of a request that sets none. The host default (30 s) would let two hung requests fill a chunk.
const DEFAULT_TIMEOUT_MS: u32 = 10_000;

/// Sends HTTP requests. Implemented by the host in production and by [`FakeHttp`] in tests.
pub trait Http {
    /// Sends `request` and returns the response, or a transport error message.
    fn send(&self, request: &HttpRequest) -> Result<HttpResponse, String>;
}

/// Sends requests through the IDE host.
pub struct HostHttp;

impl Http for HostHttp {
    fn send(&self, request: &HttpRequest) -> Result<HttpResponse, String> {
        host::fetch(&with_default_timeout(request)).map_err(|error| error.to_string())
    }
}

/// Returns `request` with [`DEFAULT_TIMEOUT_MS`] when it sets no timeout. Otherwise borrows it unchanged.
fn with_default_timeout(request: &HttpRequest) -> Cow<'_, HttpRequest> {
    if request.timeout_ms.is_some() {
        return Cow::Borrowed(request);
    }
    Cow::Owned(HttpRequest {
        timeout_ms: Some(DEFAULT_TIMEOUT_MS),
        ..request.clone()
    })
}

#[cfg(test)]
mod timeout_tests {
    use super::*;

    #[test]
    fn request_without_timeout_gets_the_default() {
        let request = HttpRequest::get("https://pypi.org/pypi/requests/json");
        let bounded = with_default_timeout(&request);
        assert_eq!(bounded.timeout_ms, Some(DEFAULT_TIMEOUT_MS));
        assert_eq!(bounded.url, request.url);
    }

    #[test]
    fn request_with_its_own_timeout_is_unchanged() {
        let request = HttpRequest {
            timeout_ms: Some(3_000),
            ..HttpRequest::get("https://pypi.org/pypi/requests/json")
        };
        let bounded = with_default_timeout(&request);
        assert!(matches!(bounded, Cow::Borrowed(_)));
        assert_eq!(bounded.timeout_ms, Some(3_000));
    }
}

/// A canned answer for requests whose method and URL prefix match.
#[cfg(test)]
struct FakeRoute {
    method: String,
    url_prefix: String,
    /// Status and body on success, or the transport error message.
    outcome: Result<(u16, Vec<u8>), String>,
}

/// A recorded request: method, URL and UTF-8 body (empty when there is none).
#[cfg(test)]
struct RecordedRequest {
    method: String,
    url: String,
    body: String,
}

/// Test double for [`Http`] that answers from canned routes and records every request.
#[cfg(test)]
#[derive(Default)]
pub struct FakeHttp {
    routes: Vec<FakeRoute>,
    requests: std::cell::RefCell<Vec<RecordedRequest>>,
}

#[cfg(test)]
impl FakeHttp {
    /// Creates a fake without routes.
    pub fn new() -> Self {
        Self::default()
    }

    /// Answers `method` requests whose URL starts with `url_prefix` with `status` and `body`.
    pub fn route(mut self, method: &str, url_prefix: &str, status: u16, body: &str) -> Self {
        self.routes.push(FakeRoute {
            method: method.to_owned(),
            url_prefix: url_prefix.to_owned(),
            outcome: Ok((status, body.as_bytes().to_vec())),
        });
        self
    }

    /// Fails `method` requests whose URL starts with `url_prefix` with a transport error.
    pub fn transport_error(mut self, method: &str, url_prefix: &str, message: &str) -> Self {
        self.routes.push(FakeRoute {
            method: method.to_owned(),
            url_prefix: url_prefix.to_owned(),
            outcome: Err(message.to_owned()),
        });
        self
    }

    /// Returns `(method, url)` of every request, in call order.
    pub fn requests(&self) -> Vec<(String, String)> {
        self.requests
            .borrow()
            .iter()
            .map(|recorded| (recorded.method.clone(), recorded.url.clone()))
            .collect()
    }

    /// Returns the body of every request, in call order (empty when there is none).
    pub fn request_bodies(&self) -> Vec<String> {
        self.requests
            .borrow()
            .iter()
            .map(|recorded| recorded.body.clone())
            .collect()
    }

    /// Counts the requests whose URL starts with `url_prefix`.
    pub fn count(&self, url_prefix: &str) -> usize {
        self.requests
            .borrow()
            .iter()
            .filter(|recorded| recorded.url.starts_with(url_prefix))
            .count()
    }
}

#[cfg(test)]
impl Http for FakeHttp {
    fn send(&self, request: &HttpRequest) -> Result<HttpResponse, String> {
        let body = String::from_utf8_lossy(request.body.as_deref().unwrap_or_default());
        self.requests.borrow_mut().push(RecordedRequest {
            method: request.method.clone(),
            url: request.url.clone(),
            body: body.into_owned(),
        });
        let route = self
            .routes
            .iter()
            .find(|route| {
                route.method == request.method && request.url.starts_with(&route.url_prefix)
            })
            .ok_or_else(|| format!("no route for {} {}", request.method, request.url))?;
        match &route.outcome {
            Ok((status, body)) => Ok(HttpResponse {
                status: *status,
                headers: Vec::new(),
                body: body.clone(),
            }),
            Err(message) => Err(message.clone()),
        }
    }
}
