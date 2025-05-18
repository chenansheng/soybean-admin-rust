use std::net::SocketAddr;

use tokio::net::TcpListener;

#[tokio::main]
async fn main() {
    let config_path = if cfg!(debug_assertions) {
        "server/resources/application-test.yaml"
    } else {
        "server/resources/application.yaml"
    };

    // 初始化日志追踪和配置
    server_initialize::initialize_log_tracing().await;
    // 初始化配置
    server_initialize::initialize_config(config_path).await;
    // 初始化数据库连接池和验证器
    let _ = server_initialize::init_xdb().await;
    // 初始化主数据库连接池和验证器
    server_initialize::init_primary_connection().await;
    // 初始化数据库连接池和验证器
    server_initialize::init_db_pools().await;
    // 初始化JWT密钥和验证器
    server_initialize::initialize_keys_and_validation().await;
    // 初始化事件通道
    server_initialize::initialize_event_channel().await;
    // 初始化Redis连接池和验证器
    server_initialize::init_primary_redis().await;
    // pass
    server_initialize::init_redis_pools().await;
    server_initialize::init_primary_mongo().await;
    server_initialize::init_mongo_pools().await;
    // 创建路由
    let app = server_initialize::initialize_admin_router().await;
    //需要初始化验证器init_validators之后才能初始化访问密钥
    server_initialize::initialize_access_key().await;

    let addr = match server_initialize::get_server_address().await {
        Ok(addr) => addr,
        Err(e) => {
            eprintln!("Failed to get server address: {}", e);
            return;
        },
    };

    // run it
    let listener = TcpListener::bind(&addr).await.unwrap();
    // tracing::debug!("listening on {}", listener.local_addr().unwrap());
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .unwrap();
}
