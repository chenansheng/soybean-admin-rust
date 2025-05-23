pub use access_key_initialization::initialize_access_key;
pub use aws_s3_initialization::{init_primary_s3, init_s3_pools};
pub use casbin_initialization::initialize_casbin;
pub use config_initialization::initialize_config;
pub use db_initialization::{init_db_pools, init_primary_connection};
pub use event_channel_initialization::initialize_event_channel;
pub use ip2region_initialization::init_xdb;
pub use jwt_initialization::initialize_keys_and_validation;
pub use log_tracing_init::initialize_log_tracing;
pub use mongo_initialization::{init_mongo_pools, init_primary_mongo};
pub use redis_initialization::{init_primary_redis, init_redis_pools};
pub use router_initialization::initialize_admin_router;
pub use server_global::{project_error, project_info};
pub use server_initialization::get_server_address;
pub use service_initialization::initialize_service_config;

mod access_key_initialization;
mod aws_s3_initialization;
mod casbin_initialization;
mod config_initialization;
mod db_initialization;
mod event_channel_initialization;
mod ip2region_initialization;
mod jwt_initialization;
mod log_tracing_init;
mod mongo_initialization;
mod redis_initialization;
mod router_initialization;
mod server_initialization;
mod service_initialization;

// TODO: axum_test_helpers不兼容axum 0.8.x
// #[cfg(test)]
// mod tests {
//     use std::{
//         convert::Infallible,
//         task::{Context, Poll},
//     };

//     use axum::{body::HttpBody, response::Response, routing::get, BoxError, Router};
//     use axum_casbin::CasbinVals;
//     use axum_test_helpers::TestClient;
//     use bytes::Bytes;
//     use casbin::{function_map::key_match2, CoreApi};
//     use futures::future::BoxFuture;
//     use http::{Request, StatusCode};
//     use log::LevelFilter;
//     use server_config::DatabaseConfig;
//     use server_global::global;
//     use simplelog::{Config as LogConfig, SimpleLogger};
//     use tower::Service;

//     use super::*;

//     static INIT: std::sync::Once = std::sync::Once::new();

//     fn init_logger() {
//         INIT.call_once(|| {
//             SimpleLogger::init(LevelFilter::Info, LogConfig::default()).unwrap();
//         });
//     }

//     #[tokio::test]
//     async fn test_initialize_config() {
//         init_logger();

//         initialize_config("../resources/application-test.yaml").await;

//         let db_config = global::get_config::<DatabaseConfig>().await.unwrap();
//         assert_eq!(db_config.url, "postgres://user:password@localhost/db");
//     }

//     #[tokio::test]
//     async fn test_initialize_casbin() {
//         init_logger();

//         let result = initialize_casbin(
//             "../resources/rbac_model.conf",
//             "postgres://postgres:123456@localhost:5432/soybean-admin-rust-backend",
//         )
//         .await;
//         assert!(result.is_ok());
//     }

//     #[tokio::test]
//     async fn test_initialize_casbin_with_axum() {
//         init_logger();

//         let casbin_middleware = initialize_casbin(
//             "../resources/rbac_model.conf",
//             "postgres://postgres:123456@localhost:5432/soybean-admin-rust-backend",
//         )
//         .await
//         .unwrap();

//         casbin_middleware
//             .write()
//             .await
//             .get_role_manager()
//             .write()
//             .matching_fn(Some(key_match2), None);

//         let app = Router::new()
//             .route("/pen/1", get(handler))
//             .route("/pen/2", get(handler))
//             .route("/book/:id", get(handler))
//             .layer(casbin_middleware)
//             .layer(FakeAuthLayer);

//         let client = TestClient::new(app);

//         let resp_pen_1 = client.get("/pen/1").await;
//         assert_eq!(resp_pen_1.status(), StatusCode::OK);

//         let resp_book = client.get("/book/2").await;
//         assert_eq!(resp_book.status(), StatusCode::OK);

//         let resp_pen_2 = client.get("/pen/2").await;
//         assert_eq!(resp_pen_2.status(), StatusCode::FORBIDDEN);
//     }

//     async fn handler() -> &'static str {
//         "Hello, world!"
//     }

//     #[derive(Clone)]
//     struct FakeAuthLayer;

//     impl<S> tower::Layer<S> for FakeAuthLayer {
//         type Service = FakeAuthMiddleware<S>;

//         fn layer(&self, inner: S) -> Self::Service {
//             FakeAuthMiddleware { inner }
//         }
//     }

//     #[derive(Clone)]
//     struct FakeAuthMiddleware<S> {
//         inner: S,
//     }

//     impl<S, ReqBody, ResBody> Service<Request<ReqBody>> for FakeAuthMiddleware<S>
//     where
//         S: Service<Request<ReqBody>, Response = Response<ResBody>, Error = Infallible>
//             + Clone
//             + Send
//             + 'static,
//         S::Future: Send + 'static,
//         ReqBody: Send + 'static,
//         Infallible: From<<S as Service<Request<ReqBody>>>::Error>,
//         ResBody: HttpBody<Data = Bytes> + Send + 'static,
//         ResBody::Error: Into<BoxError>,
//     {
//         type Error = S::Error;
//         // `BoxFuture` is a type alias for `Pin<Box<dyn Future + Send + 'a>>`
//         type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;
//         type Response = S::Response;

//         fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
//             self.inner.poll_ready(cx)
//         }

//         fn call(&mut self, mut req: Request<ReqBody>) -> Self::Future {
//             let not_ready_inner = self.inner.clone();
//             let mut inner = std::mem::replace(&mut self.inner, not_ready_inner);

//             Box::pin(async move {
//                 let vals = CasbinVals {
//                     subject: vec!["alice".to_string()],
//                     domain: None,
//                 };
//                 req.extensions_mut().insert(vals);
//                 inner.call(req).await
//             })
//         }
//     }
// }
