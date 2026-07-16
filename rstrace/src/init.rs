use std::{fmt::Display, str::FromStr};

#[derive(clap::Parser)]
pub struct InitArg {
    manifest: Option<String>,
    #[arg(long)]
    region: String,
    ///cu/ct/cm
    #[arg(long)]
    not: Isp,
}
#[derive(Clone)]
enum Isp {
    Cu,
    Ct,
    Cm,
}
impl Display for Isp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Isp::Cu => "cu",
            Isp::Ct => "ct",
            Isp::Cm => "cm",
        })
    }
}
impl FromStr for Isp {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s.to_lowercase().as_str() {
            "cu" => Self::Cu,
            "ct" => Self::Ct,
            "cm" => Self::Cm,
            _ => return Err("cu/ct/cm"),
        })
    }
}
async fn get_content_by_url(src: &str, decrypt: bool) -> anyhow::Result<Vec<u8>> {
    let content = if src.starts_with("http://") || src.starts_with("https://") {
        let resp = reqwest::get(src).await?;
        if resp.status() != 200 {
            return Err(anyhow::anyhow!("manifest return no200 {}", resp.status()));
        }
        let content = resp.bytes().await?;
        if decrypt {
            crate::util::decrypt(&content).unwrap_or(content.to_vec())
        } else {
            content.to_vec()
        }
    } else {
        tokio::fs::read(src).await?
    };
    Ok(content)
}
pub async fn run_init(arg: InitArg) -> anyhow::Result<()> {
    let manifest = arg
        .manifest
        .unwrap_or("https://qiniu0x1.oss-cn-chengdu.aliyuncs.com/iplib/manifest.json".to_string());
    let content = get_content_by_url(&manifest, true).await?;
    let manifest = serde_json::from_slice::<Manifest>(&content)?;
    let cfg = manifest
        .province
        .get(&arg.region)
        .ok_or(anyhow::anyhow!("region not in manifest"))?;
    let url = match arg.not.clone() {
        Isp::Cu => cfg.not_cu.as_ref(),
        Isp::Ct => cfg.not_ct.as_ref(),
        Isp::Cm => cfg.not_cm.as_ref(),
    }
    .ok_or(anyhow::anyhow!("manifest not describe not this isp"))?;
    let content = get_content_by_url(url, false).await?;
    tokio::fs::write(
        std::path::PathBuf::new().join("/etc/.ip_blacklist"),
        content,
    )
    .await?;
    Ok(())
}
#[derive(serde::Deserialize)]
struct Manifest {
    version: u64,
    province: std::collections::HashMap<String, Province>,
}
#[derive(serde::Deserialize)]
struct Province {
    not_cu: Option<String>,
    not_ct: Option<String>,
    not_cm: Option<String>,
}
