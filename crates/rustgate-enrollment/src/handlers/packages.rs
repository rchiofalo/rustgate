//! Data package upload, download, and search handlers.

use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::{Request, Response, StatusCode};

use super::util::{build_response, extract_param};
use crate::auth::Credentials;
use crate::datapackage::DataPackageStore;

/// Handle data package upload via multipart or raw body.
pub(crate) async fn handle_package_upload(
    req: Request<hyper::body::Incoming>,
    credentials: &Credentials,
    packages: Option<&DataPackageStore>,
) -> Response<Full<Bytes>> {
    let Some(store) = packages else {
        return build_response(
            StatusCode::NOT_FOUND,
            "text/plain",
            Bytes::from("data package storage not configured"),
        );
    };

    // Require Basic Auth for uploads
    let auth_header = req
        .headers()
        .get(hyper::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok());

    let Some(username) = credentials.validate(auth_header) else {
        let mut resp = build_response(
            StatusCode::UNAUTHORIZED,
            "text/plain",
            Bytes::from("unauthorized"),
        );
        let _ = resp.headers_mut().insert(
            "WWW-Authenticate",
            hyper::header::HeaderValue::from_static("Basic realm=\"rustgate-enrollment\""),
        );
        return resp;
    };

    let content_type_hdr = req
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    // Read body (limit to 50 MiB + overhead for multipart headers)
    let limited = Limited::new(req.into_body(), 52_428_800);
    let body = match limited.collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(_) => {
            return build_response(
                StatusCode::BAD_REQUEST,
                "text/plain",
                Bytes::from("upload too large"),
            );
        }
    };

    // Extract file data from multipart body or use raw body
    let (file_data, filename) =
        if let Some(boundary) = crate::datapackage::extract_boundary(&content_type_hdr) {
            let name = crate::datapackage::extract_multipart_filename(&body, boundary)
                .unwrap_or_else(|| "upload.zip".to_string());
            let data = crate::datapackage::extract_multipart_field(&body, boundary, "assetfile")
                .unwrap_or(&body);
            (data.to_vec(), name)
        } else {
            (body.to_vec(), "upload.zip".to_string())
        };

    match store.upload(&file_data, &filename, username).await {
        Ok(meta) => {
            let json = serde_json::json!({
                "Hash": meta.hash,
                "Name": meta.name,
                "Size": meta.size,
            });
            build_response(
                StatusCode::OK,
                "application/json",
                Bytes::from(json.to_string()),
            )
        }
        Err(e) => {
            tracing::warn!(error = %e, "data package upload failed");
            build_response(
                StatusCode::BAD_REQUEST,
                "text/plain",
                Bytes::from("upload failed"),
            )
        }
    }
}

/// Handle data package download by hash.
pub(crate) async fn handle_package_download(
    req: Request<hyper::body::Incoming>,
    packages: Option<&DataPackageStore>,
) -> Response<Full<Bytes>> {
    let Some(store) = packages else {
        return build_response(
            StatusCode::NOT_FOUND,
            "text/plain",
            Bytes::from("data package storage not configured"),
        );
    };

    let hash = req
        .uri()
        .query()
        .and_then(|q| extract_param(q, "hash"))
        .unwrap_or_default();

    if hash.is_empty() {
        return build_response(
            StatusCode::BAD_REQUEST,
            "text/plain",
            Bytes::from("missing hash parameter"),
        );
    }

    match store.download(&hash).await {
        Ok((_meta, data)) => build_response(
            StatusCode::OK,
            "application/x-zip-compressed",
            Bytes::from(data),
        ),
        Err(_) => build_response(
            StatusCode::NOT_FOUND,
            "text/plain",
            Bytes::from("package not found"),
        ),
    }
}

/// Handle data package search by keyword.
pub(crate) async fn handle_package_search(
    req: Request<hyper::body::Incoming>,
    packages: Option<&DataPackageStore>,
) -> Response<Full<Bytes>> {
    let Some(store) = packages else {
        return build_response(
            StatusCode::NOT_FOUND,
            "text/plain",
            Bytes::from("data package storage not configured"),
        );
    };

    let keyword = req
        .uri()
        .query()
        .and_then(|q| extract_param(q, "keyword"))
        .unwrap_or_default();

    match store.search(&keyword).await {
        Ok(results) => {
            let json = serde_json::to_string(&results).unwrap_or_else(|_| "[]".to_string());
            build_response(StatusCode::OK, "application/json", Bytes::from(json))
        }
        Err(e) => {
            tracing::warn!(error = %e, "data package search failed");
            build_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "text/plain",
                Bytes::from("search failed"),
            )
        }
    }
}
