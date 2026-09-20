use super::*;
use http_body_util::BodyExt;
const BODY_TIMEOUT: Duration = Duration::from_secs(5);
impl Peer {
    pub(super) fn check_continuity_request<B>(
        &self,
        request: &Request<B>,
    ) -> Result<(wire::Request, bool, Option<usize>), StatusCode> {
        if request.version() != hyper::Version::HTTP_11
            || request.uri().scheme().is_some()
            || request.uri().authority().is_some()
        {
            return Err(StatusCode::BAD_REQUEST);
        }
        let headers = request.headers();
        for name in [
            header::COOKIE,
            header::AUTHORIZATION,
            header::PROXY_AUTHORIZATION,
            header::EXPECT,
            header::UPGRADE,
            header::CONTENT_ENCODING,
        ] {
            if headers.contains_key(name) {
                return Err(StatusCode::BAD_REQUEST);
            }
        }
        let expected_host = self
            .config
            .public_endpoint
            .as_str()
            .strip_prefix("https://")
            .and_then(|s| s.strip_suffix("/vhalla/v1"))
            .ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;
        let host = single(headers, header::HOST.as_str())?;
        if host.is_none()
            || (host != Some(expected_host) && host != expected_host.strip_suffix(":443"))
        {
            return Err(StatusCode::MISDIRECTED_REQUEST);
        }
        if let Some(origin) = single(headers, header::ORIGIN.as_str())? {
            if origin != self.config.allowed_origin.as_str() {
                return Err(StatusCode::FORBIDDEN);
            }
        }
        let typed =
            wire::Request::parse_target(request.uri().path_and_query().map_or("", |p| p.as_str()))
                .map_err(|_| StatusCode::BAD_REQUEST)?;
        let preflight = request.method() == Method::OPTIONS;
        let method = if typed.method() == "POST" {
            Method::POST
        } else {
            Method::GET
        };
        if !preflight && request.method() != method {
            return Err(StatusCode::METHOD_NOT_ALLOWED);
        }
        let length = single(headers, header::CONTENT_LENGTH.as_str())?
            .map(|value| {
                if value.is_empty()
                    || (value.len() > 1 && value.starts_with('0'))
                    || !value.bytes().all(|b| b.is_ascii_digit())
                {
                    return Err(StatusCode::BAD_REQUEST);
                }
                value.parse::<usize>().map_err(|_| StatusCode::BAD_REQUEST)
            })
            .transpose()?;
        let transfer = single(headers, header::TRANSFER_ENCODING.as_str())?;
        if transfer.is_some() && (transfer != Some("chunked") || length.is_some()) {
            return Err(StatusCode::BAD_REQUEST);
        }
        if preflight {
            if single(headers, header::ORIGIN.as_str())?.is_none()
                || single(headers, header::ACCESS_CONTROL_REQUEST_METHOD.as_str())?
                    != Some(method.as_str())
                || single(headers, header::ACCESS_CONTROL_REQUEST_HEADERS.as_str())?
                    .is_some_and(|value| value != "content-type")
                || transfer.is_some()
                || length.is_some_and(|n| n != 0)
            {
                return Err(StatusCode::BAD_REQUEST);
            }
        } else if method == Method::POST {
            if single(headers, header::CONTENT_TYPE.as_str())? != Some("application/octet-stream") {
                return Err(StatusCode::UNSUPPORTED_MEDIA_TYPE);
            }
            if length.is_some_and(|n| n == 0 || n > wire::MAX_BODY_BYTES) {
                return Err(StatusCode::PAYLOAD_TOO_LARGE);
            }
            if length.is_none() && transfer.is_none() {
                return Err(StatusCode::LENGTH_REQUIRED);
            }
        } else if transfer.is_some() || length.is_some_and(|n| n != 0) {
            return Err(StatusCode::BAD_REQUEST);
        }
        Ok((typed, preflight, length))
    }
    pub(in crate::unix) async fn handle_continuity(
        self: Arc<Self>,
        request: Request<Incoming>,
        permit: Arc<Permit>,
    ) -> Result<Response<Full<Bytes>>, Infallible> {
        let (typed, preflight, length) = match self.check_continuity_request(&request) {
            Ok(value) => value,
            Err(status) => return Ok(failure(status)),
        };
        let origin = self.config.allowed_origin.as_str().to_owned();
        if preflight {
            match self.activity.try_lock() {
                Ok(slot) if matches!(slot.as_ref(), Some(activity::Owner::Continuity(_))) => {}
                Ok(_) => return Ok(activity_failure(StatusCode::NOT_FOUND, &origin)),
                Err(_) => return Ok(activity_failure(StatusCode::SERVICE_UNAVAILABLE, &origin)),
            }
            let mut response = Response::new(Full::new(Bytes::new()));
            *response.status_mut() = StatusCode::NO_CONTENT;
            cors(response.headers_mut(), &origin);
            response.headers_mut().insert(
                header::ACCESS_CONTROL_ALLOW_METHODS,
                header::HeaderValue::from_static("GET, POST"),
            );
            response.headers_mut().insert(
                header::ACCESS_CONTROL_ALLOW_HEADERS,
                header::HeaderValue::from_static("content-type"),
            );
            return Ok(response);
        }
        // Charge the checked structural request before body allocation, signatures
        // or certified replay. A dropped request consumes this process-local cost.
        let reservation = match self.reserve_continuity(typed, permit.ip) {
            Ok(value) => value,
            Err(status) => return Ok(activity_failure(status, &origin)),
        };
        let body = match timeout(
            BODY_TIMEOUT,
            read_body(request.into_body(), length, typed.method() == "POST"),
        )
        .await
        {
            Ok(Ok(body)) => body,
            Ok(Err(status)) => return Ok(activity_failure(status, &origin)),
            Err(_) => return Ok(activity_failure(StatusCode::REQUEST_TIMEOUT, &origin)),
        };
        let work = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            self.continuity_answer(reservation, &body)
        });
        let response = match timeout(READ_TIMEOUT, work).await {
            Ok(Ok(Ok((body, proof)))) => {
                let mut response = Response::new(Full::new(body));
                cors(response.headers_mut(), &origin);
                let Ok(proof) = header::HeaderValue::from_str(&proof) else {
                    return Ok(activity_failure(StatusCode::INTERNAL_SERVER_ERROR, &origin));
                };
                response.headers_mut().insert(PROOF_HEADER, proof);
                response
            }
            Ok(Ok(Err(status))) => activity_failure(status, &origin),
            _ => activity_failure(StatusCode::SERVICE_UNAVAILABLE, &origin),
        };
        Ok(response)
    }
}
async fn read_body(
    mut body: Incoming,
    expected: Option<usize>,
    post: bool,
) -> Result<Vec<u8>, StatusCode> {
    let mut bytes = Vec::new();
    while let Some(frame) = body.frame().await {
        let data = frame
            .map_err(|_| StatusCode::BAD_REQUEST)?
            .into_data()
            .map_err(|_| StatusCode::BAD_REQUEST)?;
        let next = bytes
            .len()
            .checked_add(data.len())
            .filter(|n| *n <= if post { wire::MAX_BODY_BYTES } else { 0 })
            .ok_or(StatusCode::PAYLOAD_TOO_LARGE)?;
        bytes
            .try_reserve(data.len())
            .map_err(|_| StatusCode::PAYLOAD_TOO_LARGE)?;
        bytes.extend_from_slice(&data);
        debug_assert_eq!(bytes.len(), next);
    }
    if expected.is_some_and(|len| len != bytes.len()) || (post && bytes.is_empty()) {
        return Err(StatusCode::BAD_REQUEST);
    }
    Ok(bytes)
}
