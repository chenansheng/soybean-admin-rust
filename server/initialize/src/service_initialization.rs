use server_global::global;
use server_service::admin::{SysAccessKeyService, SysAuthService, SysAuthorizationService, SysDomainService, SysEndpointService, SysLoginLogService, SysMenuService, SysOperationLogService, SysOrganizationService, SysRoleService, SysUserService};

pub async fn initialize_service_config() {
    global::init_service_config::<SysAuthService>("auth", SysAuthService).await;
    global::init_service_config::<SysAuthorizationService>("authorization", SysAuthorizationService).await;
    global::init_service_config::<SysMenuService>("menu", SysMenuService).await;
    global::init_service_config::<SysUserService>("user", SysUserService).await;
    global::init_service_config::<SysDomainService>("domain", SysDomainService).await;
    global::init_service_config::<SysRoleService>("role", SysRoleService).await;
    global::init_service_config::<SysEndpointService>("endpoint", SysEndpointService).await;
    global::init_service_config::<SysAccessKeyService>("access_key", SysAccessKeyService).await;
    global::init_service_config::<SysLoginLogService>("login_log", SysLoginLogService).await;
    global::init_service_config::<SysOperationLogService>("operation_log", SysOperationLogService).await;
    global::init_service_config::<SysOrganizationService>("organization", SysOrganizationService).await;
    global::init_service_config::<std::marker::PhantomData::<()>>("None", std::marker::PhantomData::<()>).await;
}
