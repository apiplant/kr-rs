//! Docker credential helpers (`credHelpers`, `credsStore`) run through `auth::docker_config`.
use std::os::unix::fs::PermissionsExt;

#[test]
fn helpers_supply_credentials() {
    let dir = std::env::temp_dir().join(format!("kr-credhelper-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let helper = dir.join("docker-credential-fake");
    std::fs::write(
        &helper,
        "#!/bin/sh\ncase \"$1\" in\n list) echo '{\"store.io\":\"u\"}';;\n get) read s; case \"$s\" in tok.io) echo '{\"ServerURL\":\"tok.io\",\"Username\":\"<token>\",\"Secret\":\"T0K\"}';; *) echo \"{\\\"ServerURL\\\":\\\"$s\\\",\\\"Username\\\":\\\"bob\\\",\\\"Secret\\\":\\\"pw-$s\\\"}\";; esac;;\nesac\n",
    )
    .unwrap();
    std::fs::set_permissions(&helper, std::fs::Permissions::from_mode(0o755)).unwrap();
    std::fs::write(dir.join("config.json"), r#"{"auths":{"plain.io":{"username":"a","password":"b"}},"credHelpers":{"helper.io":"fake","tok.io":"fake"},"credsStore":"fake"}"#).unwrap();
    let d = dir.to_str().unwrap().to_string();
    let env = move |k: &str| match k {
        "DOCKER_CONFIG" => Some(d.clone()),
        "PATH" => Some(d.clone()),
        _ => None,
    };
    let creds = kr_runtime::auth::docker_config(&env);
    let get = |host: &str| kr_runtime::auth::lookup(&creds, host, "x/y").cloned();
    assert_eq!(get("plain.io").unwrap().username, "a");
    let h = get("helper.io").unwrap();
    assert_eq!((h.username.as_str(), h.password.as_str()), ("bob", "pw-helper.io"));
    assert_eq!(get("tok.io").unwrap().identity_token.as_deref(), Some("T0K"));
    assert_eq!(get("store.io").unwrap().password, "pw-store.io");
    std::fs::remove_dir_all(&dir).ok();
}
