// 定义在其他模块中
#[macro_export]
macro_rules! merge_router {
    ($app:ident, $router:expr, $services:expr, $need_casbin:expr, $need_auth:expr, $api_validation:expr, $casbin:expr, $audience:expr) => {
        $app = $app.merge(
            apply_layers(
                $router,
                $services,
                $need_casbin,
                $need_auth,
                $api_validation,
                $casbin.clone(),
                $audience,
            )
            .await,
        );
    };
}

#[macro_export]
macro_rules! register_services {
        ($($variant:ident($type:ty)),* $(,)?) => {
            #[derive(Clone)]
            pub enum Services {
                $($variant($type)),*,
                None(std::marker::PhantomData<()>),
            }

            impl Services {
                // 自动生成添加中间件的方法
                pub fn apply_layer(self, router: Router) -> Router {
                    match self {
                        $(Services::$variant(service) => router.layer(Extension(Arc::new(service))),)*
                        Services::None(_) => router,
                    }
                }
            }
        };
    }

#[macro_export]
macro_rules! project_info {
    ($($arg:tt)+) => {{
        let span = tracing::span!(
            tracing::Level::INFO,
            module_path!(),
            file = file!(),
            line = line!(),
        );
        let _enter = span.enter();
        tracing::info!(
            target: "[soybean-admin-rust]",
            $($arg)+
        );
    }}
}

#[macro_export]
macro_rules! project_error {
    ($($arg:tt)+) => {{
        let span = tracing::span!(
            tracing::Level::ERROR,
            module_path!(),
            file = file!(),
            line = line!(),
        );
        let _enter = span.enter();
        tracing::error!(
            target: "[soybean-admin-rust]",
            $($arg)+
        );
    }}
}
