use bitcoin::{Network, PublicKey};
use clap::{arg, ArgGroup, ArgMatches, Command};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::env;
use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::path::PathBuf;
use toml;

use crate::contexts::base::generate_keys_from_secret;

#[derive(Serialize, Deserialize, Default)]
pub struct Config {
    pub keys: Keys,
}

#[derive(Serialize, Deserialize, Default)]
pub struct Keys {
    pub depositor: Option<String>,
    pub operator: Option<String>,
    pub verifier: Option<String>,
    pub withdrawer: Option<String>,
    pub verifying_key: Option<String>,
}

const BRIDGE_KEY_DIR_NAME: &str = ".bitvm-bridge";
const BRIDGE_TOML: &str = "bridge.toml";

pub struct KeysCommand {
    pub config_path: PathBuf,
}

impl KeysCommand {
    pub fn new(key_dir: Option<String>) -> Self {
        let key_dir = key_dir.map(PathBuf::from).unwrap_or_else(|| {
            let home_dir = env::var("HOME").expect("Environment variable HOME not set.");
            PathBuf::from(&home_dir).join(BRIDGE_KEY_DIR_NAME)
        });

        let config_path = key_dir.join(BRIDGE_TOML);

        // Create key directory if it doesn't exist
        if !key_dir.exists() {
            fs::create_dir_all(&key_dir)
                .expect(&format!("Failed to create {} directory", key_dir.display()));
        }

        KeysCommand { config_path }
    }

    pub fn get_command() -> Command {
        Command::new("keys")
            .short_flag('k')
            .about("Manage secret keys for different contexts")
            .after_help("The depositor, operator, verifier, and withdrawer contexts are optional and can be specified using the -d, -o, -v, and -w flags respectively. If a context is not specified, the current key configuration will be displayed. The verifying key for the zero-knowledge proof is optional and must be specified when running scenarios that involve proof verification.")
            .arg(arg!(-d --depositor <SECRET_KEY> "Secret key for depositor").required(false))
            .arg(arg!(-o --operator <SECRET_KEY> "Secret key for operator").required(false))
            .arg(arg!(-v --verifier <SECRET_KEY> "Secret key for verifier").required(false))
            .arg(arg!(-w --withdrawer <SECRET_KEY> "Secret key for withdrawer").required(false))
            .arg(arg!(-k --vk <KEY> "Zero-knowledge proof verifying key").required(false))
            .group(ArgGroup::new("context")
                .args(["depositor", "operator", "verifier", "withdrawer"]))
    }

    pub fn handle_command(&self, sub_matches: &ArgMatches) -> io::Result<()> {
        let mut config = self.read_config()?;

        if !sub_matches.args_present() {
            // If no arguments are specified, output the current key configuration.
            let keys = HashMap::from([
                ("DEPOSITOR", &config.keys.depositor),
                ("OPERATOR", &config.keys.operator),
                ("VERIFIER", &config.keys.verifier),
                ("WITHDRAWER", &config.keys.withdrawer),
                ("VERIFYING KEY", &config.keys.verifying_key),
            ]);

            if keys.values().any(|k| k.is_some()) {
                println!("Key configuration:");
                println!();

                let print_user_key = |private_key: &Option<String>, name: &str| {
                    if let Some(prvkey) = private_key {
                        println!("[{name}]:");
                        println!("  Private key: {}", prvkey);
                        println!("   Public key: {}", pubkey_of(prvkey));
                        println!();
                    }
                };

                let print_verifying_key = |verifying_key: &Option<String>, name: &str| {
                    if let Some(vk) = verifying_key {
                        println!("[{name}]:");
                        println!("          Key: {}", vk);
                        println!();
                    }
                };

                let mut name = "DEPOSITOR";
                print_user_key(keys.get(name).unwrap(), name);
                name = "OPERATOR";
                print_user_key(keys.get(name).unwrap(), name);
                name = "VERIFIER";
                print_user_key(keys.get(name).unwrap(), name);
                name = "WITHDRAWER";
                print_user_key(keys.get(name).unwrap(), name);
                name = "VERIFYING KEY";
                print_verifying_key(keys.get(name).unwrap(), name);
            } else {
                println!("No keys are configured.");
                println!();
            }

            Ok(())
        } else {
            if let Some(secret_key) = sub_matches.get_one::<String>("depositor") {
                if self.validate_key(secret_key) {
                    config.keys.depositor = Some(secret_key.clone());
                    println!(
                        "Secret key for depositor {} saved successfully!",
                        pubkey_of(secret_key)
                    );
                } else {
                    eprintln!("error: Invalid depositor secret key.");
                }
            } else if let Some(secret_key) = sub_matches.get_one::<String>("operator") {
                if self.validate_key(secret_key) {
                    config.keys.operator = Some(secret_key.clone());
                    println!(
                        "Secret key for operator {} saved successfully!",
                        pubkey_of(secret_key)
                    );
                } else {
                    eprintln!("error: Invalid operator secret key.");
                }
            } else if let Some(secret_key) = sub_matches.get_one::<String>("verifier") {
                if self.validate_key(secret_key) {
                    config.keys.verifier = Some(secret_key.clone());
                    println!(
                        "Secret key for verifier {} saved successfully!",
                        pubkey_of(secret_key)
                    );
                } else {
                    eprintln!("error: Invalid verifier secret key.");
                }
            } else if let Some(secret_key) = sub_matches.get_one::<String>("withdrawer") {
                if self.validate_key(secret_key) {
                    config.keys.withdrawer = Some(secret_key.clone());
                    println!(
                        "Secret key for withdrawer {} saved successfully!",
                        pubkey_of(secret_key)
                    );
                } else {
                    eprintln!("error: Invalid withdrawer secret key.");
                }
            } else if let Some(verifying_key) = sub_matches.get_one::<String>("vk") {
                if self.validate_verifying_key(verifying_key) {
                    config.keys.verifying_key = Some(verifying_key.clone());
                    println!("ZK proof verifying key saved successfully!");
                } else {
                    eprintln!("error: Invalid ZK proof verifying key.");
                }
            }
            self.write_config(&config)
        }
    }

    pub fn read_config(&self) -> io::Result<Config> {
        if self.config_path.exists() {
            let mut file = OpenOptions::new().read(true).open(&self.config_path)?;
            let mut content = String::new();
            file.read_to_string(&mut content)?;
            Ok(toml::from_str(&content).unwrap_or_default())
        } else {
            Ok(Config::default())
        }
    }

    pub fn write_config(&self, config: &Config) -> io::Result<()> {
        let toml_string = toml::to_string(config).expect("Failed to serialize config");
        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&self.config_path)?;
        file.write_all(toml_string.as_bytes())
    }

    fn validate_key(&self, key: &str) -> bool {
        key.len() == 64 && key.chars().all(|c| c.is_ascii_hexdigit())
    }

    // TODO: This is TBD. Verifying key validation is unclear at the moment.
    // We'll add it once circuit design is finalized and we can run a Groth16 setup.
    fn validate_verifying_key(&self, _key: &str) -> bool {
        true
    }
}

// TODO: Technically this should use the source network specified by the user. However, since this
// is only used in console output as an ID, we can leave it for now.
fn pubkey_of(private_key: &str) -> PublicKey {
    generate_keys_from_secret(Network::Bitcoin, private_key).1
}
