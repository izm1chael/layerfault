use super::*;
use reqwest::header::{CONTENT_RANGE, RANGE};
const MAX_RANGE: u64 = 32 * 1024 * 1024;
impl HubClient {
    pub(crate) fn fetch_range_verified(
        &self,
        repo: &str,
        revision: &str,
        file: &HubFile,
        offset: u64,
        length: u64,
    ) -> Result<Vec<u8>> {
        validate_repo_id(repo)?;
        validate_commit_sha(revision)?;
        validate_member_path(&file.path)?;
        if length == 0 || length > MAX_RANGE {
            bail!("range length must be 1..={MAX_RANGE}")
        }
        let end = offset
            .checked_add(length - 1)
            .ok_or_else(|| anyhow!("range overflow"))?;
        if let Some(size) = file.size {
            if end >= size {
                bail!("range exceeds declared remote object size")
            }
        }
        let mut url = Url::parse(API_BASE)?;
        {
            let mut seg = url
                .path_segments_mut()
                .map_err(|_| anyhow!("invalid Hub base URL"))?;
            for c in repo.split('/') {
                seg.push(c);
            }
            seg.push("resolve").push(revision);
            for c in Path::new(&file.path).components() {
                if let Component::Normal(v) = c {
                    seg.push(&v.to_string_lossy());
                }
            }
        }
        for redirect in 0..=MAX_REDIRECTS {
            validate_url(&url)?;
            let mut req = self
                .client
                .get(url.clone())
                .header(USER_AGENT, &self.user_agent)
                .header(RANGE, format!("bytes={offset}-{end}"));
            if url.host_str() == Some("huggingface.co") {
                if let Some(token) = &self.token {
                    req = req.header(AUTHORIZATION, format!("Bearer {token}"));
                }
            }
            let mut response = req
                .send()
                .with_context(|| format!("Hub range request failed for {url}"))?;
            if response.status().is_redirection() {
                if redirect == MAX_REDIRECTS {
                    bail!("Hub range redirect limit exceeded")
                }
                let location = response
                    .headers()
                    .get(LOCATION)
                    .ok_or_else(|| anyhow!("Hub redirect lacks Location header"))?
                    .to_str()?;
                url = url.join(location)?;
                continue;
            }
            if response.status().as_u16() != 206 {
                bail!(
                    "Hub server did not honor bounded Range request (HTTP {})",
                    response.status()
                )
            }
            let content_range = response
                .headers()
                .get(CONTENT_RANGE)
                .and_then(|v| v.to_str().ok())
                .ok_or_else(|| anyhow!("range response lacks Content-Range"))?;
            if !content_range.starts_with(&format!("bytes {offset}-{end}/")) {
                bail!("unexpected Content-Range '{content_range}'")
            }
            let mut out = Vec::with_capacity(length as usize);
            let mut buf = [0u8; 64 * 1024];
            loop {
                let n = response.read(&mut buf)?;
                if n == 0 {
                    break;
                }
                if out.len().saturating_add(n) > length as usize {
                    bail!("range response exceeds requested byte cap")
                }
                out.extend_from_slice(&buf[..n]);
            }
            if out.len() != length as usize {
                bail!("short range response: expected {length}, got {}", out.len())
            }
            return Ok(out);
        }
        bail!("Hub range redirect processing failed")
    }
}
