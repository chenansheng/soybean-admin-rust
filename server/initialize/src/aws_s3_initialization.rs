#![allow(dead_code)]
use std::{process, sync::Arc};

use aws_config::BehaviorVersion;
use aws_sdk_s3::{
    config::{Credentials, Region},
    Client as S3Client,
};
use server_config::{OptionalConfigs, S3Config, S3InstancesConfig};
use server_global::global::{get_config, GLOBAL_PRIMARY_S3, GLOBAL_S3_POOL};

use crate::{project_error, project_info};

/// 初始化主 S3 客户端
pub async fn init_primary_s3() {
    if let Some(config) = get_config::<S3Config>().await {
        match create_s3_client(&config).await {
            Ok(client) => {
                *GLOBAL_PRIMARY_S3.write().await = Some(Arc::new(client));
                project_info!("Primary S3 client initialized");
            },
            Err(e) => {
                project_error!("Failed to initialize primary S3 client: {}", e);
                process::exit(1);
            },
        }
    }
}

/// 初始化所有 S3 客户端
pub async fn init_s3_pools() {
    if let Some(s3_instances_config) = get_config::<OptionalConfigs<S3InstancesConfig>>().await {
        if let Some(s3_instances) = &s3_instances_config.configs {
            let _ = init_s3_pool(Some(s3_instances.clone())).await;
        }
    }
}

pub async fn init_s3_pool(
    s3_instances_config: Option<Vec<S3InstancesConfig>>,
) -> Result<(), String> {
    if let Some(s3_instances) = s3_instances_config {
        for s3_instance in s3_instances {
            init_s3_connection(&s3_instance.name, &s3_instance.s3).await?;
        }
    }
    Ok(())
}

async fn init_s3_connection(name: &str, config: &S3Config) -> Result<(), String> {
    match create_s3_client(config).await {
        Ok(client) => {
            let client_arc = Arc::new(client);
            GLOBAL_S3_POOL
                .write()
                .await
                .insert(name.to_string(), client_arc);
            project_info!("S3 client '{}' initialized", name);
            Ok(())
        },
        Err(e) => {
            let error_msg = format!("Failed to initialize S3 client '{}': {}", name, e);
            project_error!("{}", error_msg);
            Err(error_msg)
        },
    }
}

async fn create_s3_client(config: &S3Config) -> Result<S3Client, String> {
    let mut aws_config_builder =
        aws_config::defaults(BehaviorVersion::latest()).region(Region::new(config.region.clone()));

    if let Some(endpoint) = &config.endpoint {
        aws_config_builder = aws_config_builder.endpoint_url(endpoint);
    }

    if !config.access_key_id.is_empty() && !config.secret_access_key.is_empty() {
        aws_config_builder = aws_config_builder.credentials_provider(Credentials::new(
            config.access_key_id.clone(),
            config.secret_access_key.clone(),
            None,
            None,
            "soybean-admin-rust",
        ));
    }

    let aws_config = aws_config_builder.load().await;
    let client = S3Client::new(&aws_config);

    // 验证 S3 客户端连接
    match client.list_buckets().send().await {
        Ok(_) => Ok(client),
        Err(e) => Err(format!("Failed to connect to S3: {}", e)),
    }
}

/// 获取主要的 S3 客户端
pub async fn get_primary_s3_client() -> Option<Arc<S3Client>> {
    GLOBAL_PRIMARY_S3.read().await.clone()
}

/// 获取命名的 S3 客户端
pub async fn get_s3_pool_connection(name: &str) -> Option<Arc<S3Client>> {
    GLOBAL_S3_POOL.read().await.get(name).cloned()
}

/// 添加或更新 S3 客户端池中的客户端
pub async fn add_or_update_s3_pool(name: &str, config: &S3Config) -> Result<(), String> {
    init_s3_connection(name, config).await
}

/// 移除命名的 S3 客户端
pub async fn remove_s3_pool(name: &str) -> Result<(), String> {
    let mut s3_pool = GLOBAL_S3_POOL.write().await;
    s3_pool
        .remove(name)
        .ok_or_else(|| format!("S3 client '{}' not found", name))?;
    project_info!("S3 client '{}' removed", name);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::initialize_config;
    use aws_sdk_s3::types::{BucketLocationConstraint, CreateBucketConfiguration};
    use log::LevelFilter;
    use simple_logger::SimpleLogger;
    use tokio::sync::Mutex;

    static INITIALIZED: Mutex<Option<Arc<()>>> = Mutex::const_new(None);
    static TEST_BUCKET_NAME: &str = "test-bucket-rust-s3";

    fn setup_logger() {
        let _ = SimpleLogger::new().with_level(LevelFilter::Info).init();
    }

    async fn init() {
        let mut initialized = INITIALIZED.lock().await;
        if initialized.is_none() {
            initialize_config("../resources/application.yaml").await;
            *initialized = Some(Arc::new(()));
        }
    }

    // 测试 S3 基本操作
    async fn test_s3_operations(client: &S3Client) -> Result<(), String> {
        // 确保测试桶存在
        let bucket_exists = client
            .head_bucket()
            .bucket(TEST_BUCKET_NAME)
            .send()
            .await
            .is_ok();

        if !bucket_exists {
            let constraint =
                BucketLocationConstraint::from(client.config().region().unwrap().as_ref());
            let bucket_config = CreateBucketConfiguration::builder()
                .location_constraint(constraint)
                .build();

            client
                .create_bucket()
                .bucket(TEST_BUCKET_NAME)
                .create_bucket_configuration(bucket_config)
                .send()
                .await
                .map_err(|e| format!("Failed to create test bucket: {}", e))?;
        }

        // 上传测试对象
        let test_object_key = "test-object.txt";
        let test_content = "Hello, S3!";

        client
            .put_object()
            .bucket(TEST_BUCKET_NAME)
            .key(test_object_key)
            .body(test_content.as_bytes().to_vec().into())
            .send()
            .await
            .map_err(|e| format!("Failed to upload test object: {}", e))?;

        // 获取测试对象
        let get_response = client
            .get_object()
            .bucket(TEST_BUCKET_NAME)
            .key(test_object_key)
            .send()
            .await
            .map_err(|e| format!("Failed to get test object: {}", e))?;

        let data = get_response
            .body
            .collect()
            .await
            .map_err(|e| format!("Failed to read object data: {}", e))?;

        let content = String::from_utf8(data.into_bytes().to_vec())
            .map_err(|e| format!("Failed to convert data to string: {}", e))?;

        if content != test_content {
            return Err(format!(
                "Object content mismatch. Expected: '{}', Got: '{}'",
                test_content, content
            ));
        }

        // 删除测试对象
        client
            .delete_object()
            .bucket(TEST_BUCKET_NAME)
            .key(test_object_key)
            .send()
            .await
            .map_err(|e| format!("Failed to delete test object: {}", e))?;

        Ok(())
    }

    #[tokio::test]
    async fn test_primary_s3_connection() {
        setup_logger();
        init().await;

        init_primary_s3().await;

        let client = get_primary_s3_client().await;
        assert!(client.is_some(), "Primary S3 client does not exist");

        if let Some(client) = client {
            let result = test_s3_operations(&client).await;
            assert!(
                result.is_ok(),
                "S3 operations test failed: {:?}",
                result.err()
            );
        }
    }

    #[tokio::test]
    async fn test_s3_pool_operations() {
        setup_logger();
        init().await;

        // 使用测试配置创建测试客户端
        let test_config = S3InstancesConfig {
            name: "test_s3".to_string(),
            s3: S3Config {
                region: "us-east-1".to_string(),
                access_key_id: "test_key".to_string(),
                secret_access_key: "test_secret".to_string(),
                endpoint: Some("http://localhost:4566".to_string()),
            },
        };

        // 初始化测试S3池
        let result = init_s3_pool(Some(vec![test_config.clone()])).await;
        assert!(
            result.is_ok(),
            "Failed to initialize S3 pool: {:?}",
            result.err()
        );

        // 测试连接池连接
        let pool_connection = get_s3_pool_connection("test_s3").await;
        assert!(pool_connection.is_some(), "Pool connection not found");

        if let Some(client) = pool_connection {
            let result = test_s3_operations(&client).await;
            assert!(
                result.is_ok(),
                "S3 pool operations test failed: {:?}",
                result.err()
            );
        }

        // 测试添加新连接
        let add_result = add_or_update_s3_pool("test_new", &test_config.s3).await;
        assert!(add_result.is_ok(), "Failed to add S3 connection");

        // 测试移除连接
        let remove_result = remove_s3_pool("test_new").await;
        assert!(remove_result.is_ok(), "Failed to remove S3 connection");

        let connection_after_removal = get_s3_pool_connection("test_new").await;
        assert!(
            connection_after_removal.is_none(),
            "S3 connection still exists after removal"
        );
    }
}
