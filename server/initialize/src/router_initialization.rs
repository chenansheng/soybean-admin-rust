use std::sync::Arc;

use crate::{initialize_casbin, project_error, project_info};
use axum::{body::Body, http::StatusCode, response::IntoResponse, Extension, Router};
use axum_casbin::CasbinAxumLayer;
use chrono::Local;
use http::Request;
use server_config::Config;
use server_constant::definition::Audience;
use server_core::sign::{
    api_key_middleware, protect_route, ApiKeySource, ApiKeyValidation, ComplexApiKeyConfig,
    SimpleApiKeyConfig, ValidatorType,
};
use server_core::web::{RequestId, RequestIdLayer};
use server_global::global::{clear_routes, get_collected_routes, get_config};
use server_global::{merge_router, register_services};
use server_middleware::jwt_auth_middleware;
use server_router::admin::{
    SysAccessKeyRouter, SysAuthenticationRouter, SysDomainRouter, SysEndpointRouter,
    SysLoginLogRouter, SysMenuRouter, SysOperationLogRouter, SysOrganizationRouter, SysRoleRouter,
    SysSandboxRouter, SysUserRouter,
};
use server_service::{
    admin::{
        SysAccessKeyService, SysAuthService, SysAuthorizationService, SysDomainService,
        SysEndpointService, SysLoginLogService, SysMenuService, SysOperationLogService,
        SysOrganizationService, SysRoleService, SysUserService, TEndpointService,
    },
    SysEndpoint,
};
use tower_http::trace::TraceLayer;
use tracing::info_span;

// 使用宏生成所有服务枚举
register_services! {
    SysAuthService(SysAuthService),
    SysAuthorizationService(SysAuthorizationService),
    SysMenuService(SysMenuService),
    SysUserService(SysUserService),
    SysDomainService(SysDomainService),
    SysRoleService(SysRoleService),
    SysEndpointService(SysEndpointService),
    SysAccessKeyService(SysAccessKeyService),
    SysLoginLogService(SysLoginLogService),
    SysOperationLogService(SysOperationLogService),
    SysOrganizationService(SysOrganizationService),
}
async fn apply_layers(
    router: Router,
    services: Vec<Services>,
    need_casbin: bool,
    need_auth: bool,
    api_validation: Option<ApiKeyValidation>,
    casbin: Option<CasbinAxumLayer>,
    audience: Audience,
) -> Router {
    let mut router = router;
    // 使用迭代器折叠处理所有服务
    router = services
        .into_iter()
        .fold(router, |acc, service| service.apply_layer(acc));

    router = router
        .layer(
            TraceLayer::new_for_http().make_span_with(|request: &Request<Body>| {
                let request_id = request
                    .extensions()
                    .get::<RequestId>()
                    .map(ToString::to_string)
                    .unwrap_or_else(|| "unknown".into());
                info_span!(
                    "[soybean-admin-rust] >>>>>> request",
                    id = %request_id,
                    method = %request.method(),
                    uri = %request.uri(),
                )
            }),
        )
        .layer(RequestIdLayer);

    if need_casbin {
        if let Some(casbin) = casbin {
            router = router.layer(Extension(casbin.clone())).layer(casbin);
        }
    }

    if let Some(validation) = api_validation {
        router = router.layer(axum::middleware::from_fn(move |req, next| {
            api_key_middleware(validation.clone(), req, next)
        }));
    }

    if need_auth {
        router = router.layer(axum::middleware::from_fn(move |req, next| {
            jwt_auth_middleware(req, next, audience.as_str())
        }));
    }

    router
}

pub async fn initialize_admin_router() -> Router {
    clear_routes().await;
    project_info!("Initializing admin router");

    let app_config = get_config::<Config>().await.unwrap();
    let casbin_layer = initialize_casbin(
        "server/resources/rbac_model.conf",
        app_config.database.url.as_str(),
    )
    .await
    .unwrap();

    // 初始化验证器
    // 根据是否配置了 Redis 来选择 nonce 存储实现
    let nonce_store_factory =
        if let Some(_) = crate::redis_initialization::get_primary_redis().await {
            // 如果 Redis 可用，使用 Redis 作为 nonce 存储
            project_info!("Using Redis for nonce storage");
            server_core::sign::create_redis_nonce_store_factory("api_key")
        } else {
            // 否则使用内存存储
            project_info!("Using memory for nonce storage");
            server_core::sign::create_memory_nonce_store_factory()
        };

    server_core::sign::init_validators_with_nonce_store(None, nonce_store_factory.clone()).await;

    let simple_validation = {
        let validator = server_core::sign::get_simple_validator().await;
        server_core::sign::add_key(ValidatorType::Simple, "test-api-key", None).await;
        ApiKeyValidation::Simple(
            validator,
            SimpleApiKeyConfig {
                source: ApiKeySource::Header,
                key_name: "x-api-key".to_string(),
            },
        )
    };

    let complex_validation = {
        let validator = server_core::sign::get_complex_validator().await;
        server_core::sign::add_key(
            ValidatorType::Complex,
            "test-access-key",
            Some("test-secret-key"),
        )
        .await;
        ApiKeyValidation::Complex(
            validator,
            ComplexApiKeyConfig {
                key_name: "AccessKeyId".to_string(),
                timestamp_name: "t".to_string(),
                nonce_name: "n".to_string(),
                signature_name: "sign".to_string(),
            },
        )
    };

    // 保护路由
    protect_route("/sandbox/simple-api-key");
    protect_route("/sandbox/complex-api-key");

    let audience = Audience::ManagementPlatform;
    let casbin = Some(casbin_layer);
    let mut app = Router::new();

    merge_router!(
        app,
        SysAuthenticationRouter::init_authentication_router().await,
        vec![Services::SysAuthService(SysAuthService)],
        false,
        false,
        None,
        casbin,
        audience
    );

    merge_router!(
        app,
        SysAuthenticationRouter::init_authorization_router().await,
        vec![
            Services::SysAuthService(SysAuthService),
            Services::SysAuthorizationService(SysAuthorizationService)
        ],
        false,
        false,
        None,
        casbin,
        audience
    );

    merge_router!(
        app,
        SysAuthenticationRouter::init_protected_router().await,
        vec![Services::SysAuthService(SysAuthService)],
        false,
        true,
        None,
        casbin,
        audience
    );

    merge_router!(
        app,
        SysMenuRouter::init_menu_router().await,
        vec![Services::SysMenuService(SysMenuService)],
        false,
        false,
        None,
        casbin,
        audience
    );

    merge_router!(
        app,
        SysMenuRouter::init_protected_menu_router().await,
        vec![Services::SysMenuService(SysMenuService)],
        true,
        true,
        None,
        casbin,
        audience
    );

    merge_router!(
        app,
        SysUserRouter::init_user_router().await,
        vec![Services::SysUserService(SysUserService)],
        true,
        true,
        None,
        casbin,
        audience
    );
    
    merge_router!(
        app,
        SysDomainRouter::init_domain_router().await,
        vec![Services::SysDomainService(SysDomainService)],
        true,
        true,
        None,
        casbin,
        audience
    );
    
    merge_router!(
        app,
        SysRoleRouter::init_role_router().await,
        vec![Services::SysRoleService(SysRoleService)],
        true,
        true,
        None,
        casbin,
        audience
    );
    
    merge_router!(
        app,
        SysEndpointRouter::init_endpoint_router().await,
        vec![Services::SysEndpointService(SysEndpointService)],
        true,
        true,
        None,
        casbin,
        audience
    );
    
    merge_router!(
        app,
        SysAccessKeyRouter::init_access_key_router().await,
        vec![Services::SysAccessKeyService(SysAccessKeyService)],
        true,
        true,
        None,
        casbin,
        audience
    );
    
    merge_router!(
        app,
        SysLoginLogRouter::init_login_log_router().await,
        vec![Services::SysLoginLogService(SysLoginLogService)],
        true,
        true,
        None,
        casbin,
        audience
    );
    
    merge_router!(
        app,
        SysOperationLogRouter::init_operation_log_router().await,
        vec![Services::SysOperationLogService(SysOperationLogService)],
        true,
        true,
        None,
        casbin,
        audience
    );

    merge_router!(
        app,
        SysOrganizationRouter::init_organization_router().await,
        vec![Services::SysOrganizationService(SysOrganizationService)],
        false,
        false,
        None,
        casbin,
        audience
    );

    merge_router!(
        app,
        SysSandboxRouter::init_simple_sandbox_router().await,
        vec![Services::None(std::marker::PhantomData::<()>)],
        false,
        false,
        Some(simple_validation),
        casbin,
        audience
    );
    
    merge_router!(
        app,
        SysSandboxRouter::init_complex_sandbox_router().await,
        vec![Services::None(std::marker::PhantomData::<()>)],
        false,
        false,
        Some(complex_validation),
        casbin,
        audience
    );

    app = app.fallback(handler_404);

    process_collected_routes().await;
    project_info!("Admin router initialization completed");

    app
}

async fn handler_404() -> impl IntoResponse {
    (StatusCode::NOT_FOUND, "nothing to see here")
}

async fn process_collected_routes() {
    let routes = get_collected_routes().await;
    let endpoints: Vec<SysEndpoint> = routes
        .into_iter()
        .map(|route| {
            let resource = route.path.split('/').nth(1).unwrap_or("").to_string();
            SysEndpoint {
                id: generate_id(&route.path, &route.method.to_string()),
                path: route.path.clone(),
                method: route.method.to_string(),
                action: "rw".to_string(),
                resource,
                controller: route.service_name,
                summary: Some(route.summary),
                created_at: Local::now().naive_local(),
                updated_at: None,
            }
        })
        .collect();

    let endpoint_service = SysEndpointService;
    match endpoint_service.sync_endpoints(endpoints).await {
        Ok(_) => {
            project_info!("Endpoints synced successfully")
        },
        Err(e) => {
            project_error!("Failed to sync endpoints: {:?}", e)
        },
    }
}

fn generate_id(path: &str, method: &str) -> String {
    use std::{
        collections::hash_map::DefaultHasher,
        hash::{Hash, Hasher},
    };

    let mut hasher = DefaultHasher::new();
    format!("{}{}", path, method).hash(&mut hasher);
    format!("{:x}", hasher.finish())
}
