use url::Url;

pub fn sanitized_url(url: &Url) -> String {
    let mut safe = url.clone();
    let _ = safe.set_username("");
    let _ = safe.set_password(None);
    safe.set_fragment(None);
    if safe.query().is_some() {
        safe.set_query(Some("redacted"));
    }
    safe.to_string()
}

pub fn sanitized_location(value: &str) -> String {
    if let Ok(url) = Url::parse(value) {
        return sanitized_url(&url);
    }

    let without_fragment = value.split('#').next().unwrap_or_default();
    match without_fragment.split_once('?') {
        Some((path, _)) => format!("{path}?redacted"),
        None => without_fragment.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::{sanitized_location, sanitized_url};
    use url::Url;

    #[test]
    fn redacts_query_and_credentials() {
        let url =
            Url::parse("https://user:pass@example.com/check?token=secret#frag").expect("valid URL");
        assert_eq!(sanitized_url(&url), "https://example.com/check?redacted");
    }

    #[test]
    fn redacts_relative_location() {
        assert_eq!(
            sanitized_location("/login?return=/private#form"),
            "/login?redacted"
        );
    }
}
