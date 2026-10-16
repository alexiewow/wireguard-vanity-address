
use base64;
use rand_core::OsRng;
use x25519_dalek::{PublicKey, StaticSecret};

pub fn trial(
    targets: &[String],
    end: Option<usize>,
    case_sensitive: bool,
) -> Option<(String, String, Vec<usize>)> {
    let private = StaticSecret::new(&mut OsRng);
    let public = PublicKey::from(&private);
    let public_b64 = base64::encode(public.as_bytes());

    let search_key = if case_sensitive {
        public_b64.as_str().to_string()
    } else {
        public_b64.to_ascii_lowercase()
    };

    let mut matched = Vec::new();

    for (index, target) in targets.iter().enumerate() {
        let found = match end {
            Some(limit) => search_key[..limit].contains(target),
            None => search_key.starts_with(target),
        };

        if found {
            matched.push(index);
        }
    }

    if matched.is_empty() {
        None
    } else {
        let private_b64 = base64::encode(private.to_bytes());
        Some((private_b64, public_b64, matched))
    }
}

