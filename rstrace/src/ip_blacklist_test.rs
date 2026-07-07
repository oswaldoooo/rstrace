use anyhow::Context;
pub fn run(arg: crate::IpBlacklistTestArgs) -> anyhow::Result<()> {
    let mut bl = crate::ip_blacklist::Blacklist::new();
    bl.load_file(&arg.file)?;
    bl.sort_dedup();
    #[derive(serde::Serialize)]
    struct Element<'a> {
        target: &'a str,
        hit: bool,
    }
    if arg.stream {
        let mut target = String::new();
        let stdin = std::io::stdin();
        while let Ok(_) = stdin.read_line(&mut target) {
            let real_target = target.trim();
            if real_target.is_empty() {
                continue;
            }
            let addr: std::net::Ipv4Addr = match real_target.parse() {
                Ok(r) => r,
                Err(err) => {
                    log::error!("parse {real_target} error {err}");
                    continue;
                }
            };
            if arg.json {
                println!(
                    "{}",
                    serde_json::to_string(&Element {
                        target: real_target,
                        hit: bl.is_hit(addr)
                    })
                    .unwrap()
                )
            } else {
                println!("{real_target} {}", if bl.is_hit(addr) { 1 } else { 0 })
            };
            target.clear();
        }
    } else {
        if let Some(targets) = arg.targets {
            let result = targets
                .iter()
                .filter_map(|target| {
                    let real_target = target.trim();
                    if real_target.is_empty() {
                        return None;
                    }
                    let addr: std::net::Ipv4Addr = match real_target.parse() {
                        Ok(r) => r,
                        Err(err) => {
                            log::error!("parse {real_target} error {err}");
                            return None;
                        }
                    };
                    Some(Element {
                        target: real_target,
                        hit: bl.is_hit(addr),
                    })
                })
                .collect::<Vec<Element>>();
            if arg.json {
                println!("{}", serde_json::to_string(&result).unwrap());
            } else {
                for r in result {
                    println!("{} {}", r.target, if r.hit { 1 } else { 0 });
                }
            }
        }
    }
    Ok(())
}
