use super::{ProviderVehicle, ProviderVehicleType};
use crate::{
    app::dns::ThreadSafeDNSResolver,
    common::{
        errors::map_io_error,
        http::{HttpClient, new_http_client},
    },
};

use async_trait::async_trait;

use http_body_util::BodyExt;
use hyper::Uri;

use std::io;

use crate::common::http::DEFAULT_USER_AGENT;
use http::Request;
use std::path::{Path, PathBuf};

pub struct Vehicle {
    pub url: Uri,
    pub path: PathBuf,
    path_str: String,
    http_client: HttpClient,
}

impl Vehicle {
    pub fn new<T: Into<Uri>, P: AsRef<Path>>(
        url: T,
        path: P,
        cwd: Option<P>,
        dns_resolver: ThreadSafeDNSResolver,
    ) -> io::Result<Self> {
        // TODO(dev0): support remote content manager via proxy
        let client = new_http_client(dns_resolver, None)?;
        let path = match cwd {
            Some(cwd) => cwd.as_ref().join(path),
            None => path.as_ref().to_path_buf(),
        };
        let path_str = path.to_string_lossy().into_owned();
        Ok(Self {
            url: url.into(),
            path,
            path_str,
            http_client: client,
        })
    }
}

#[async_trait]
impl ProviderVehicle for Vehicle {
    async fn read(&self) -> std::io::Result<Vec<u8>> {
        let mut req = Request::default();
        req.headers_mut().insert(
            http::header::USER_AGENT,
            http::HeaderValue::from_static(DEFAULT_USER_AGENT),
        );
        *req.body_mut() = http_body_util::Empty::<bytes::Bytes>::new();
        *req.uri_mut() = self.url.clone();
        self.http_client
            .request(req)
            .await
            .map_err(|x| io::Error::other(x.to_string()))?
            .into_body()
            .collect()
            .await
            .map(|x| x.to_bytes().to_vec())
            .map_err(map_io_error)
    }

    fn path(&self) -> &str {
        self.path_str.as_str()
    }

    fn typ(&self) -> ProviderVehicleType {
        ProviderVehicleType::Http
    }
}

#[cfg(test)]
mod tests {
    use super::ProviderVehicle;
    use crate::{
        app::dns::{EnhancedResolver, ThreadSafeDNSResolver},
        tests::initialize,
    };
    use hyper::Uri;
    use std::{str, sync::Arc};

    #[tokio::test]
    async fn test_http_vehicle() {
        initialize();
        let u = "https://httpbin.yba.dev/base64/SFRUUEJJTiBpcyBhd2Vzb21l"
            .parse::<Uri>()
            .unwrap();
        let p = std::env::temp_dir().join("test_http_vehicle");
        let r = Arc::new(EnhancedResolver::new_default().await);
        let v =
            super::Vehicle::new(u, p, None, r.clone() as ThreadSafeDNSResolver)
                .unwrap();

        let data = v.read().await.unwrap();
        assert_eq!(str::from_utf8(&data).unwrap(), "HTTPBIN is awesome");
    }
}
