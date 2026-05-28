//! SNI-to-SAN matching logic for TLS certificate anomaly detection.
//!
//! Implements the matching rules defined in Requirement 3.4:
//! - Exact case-insensitive match between SNI hostname and SAN entry
//! - Wildcard SAN (starting with "*.") matches a single-level subdomain of the base domain

/// Check if an SNI hostname matches a single SAN entry.
///
/// A match occurs when:
/// 1. The SAN equals the SNI (case-insensitive), OR
/// 2. The SAN is a wildcard (starts with "*.") and the SNI has exactly one
///    additional subdomain label prepended to the wildcard's base domain.
///
/// # Examples
///
/// ```
/// use tlapix_analyzer::sni_match::sni_matches_san;
///
/// // Exact match (case-insensitive)
/// assert!(sni_matches_san("www.example.com", "www.example.com"));
/// assert!(sni_matches_san("WWW.Example.COM", "www.example.com"));
///
/// // Wildcard match (single-level subdomain)
/// assert!(sni_matches_san("www.example.com", "*.example.com"));
///
/// // No match: two levels deep
/// assert!(!sni_matches_san("sub.www.example.com", "*.example.com"));
///
/// // No match: bare domain (no subdomain)
/// assert!(!sni_matches_san("example.com", "*.example.com"));
/// ```
pub fn sni_matches_san(sni: &str, san: &str) -> bool {
    let sni_lower = sni.to_ascii_lowercase();
    let san_lower = san.to_ascii_lowercase();

    // Case 1: Exact case-insensitive match
    if sni_lower == san_lower {
        return true;
    }

    // Case 2: Wildcard match
    if let Some(base_domain) = san_lower.strip_prefix("*.") {
        // The base domain must not be empty
        if base_domain.is_empty() {
            return false;
        }

        // The SNI must end with ".<base_domain>"
        // and the part before that must be exactly one label (no dots)
        if let Some(subdomain) = sni_lower.strip_suffix(&format!(".{}", base_domain)).as_deref() {
            // The subdomain must be a single label: non-empty and no dots
            return !subdomain.is_empty() && !subdomain.contains('.');
        }
    }

    false
}

/// Check if an SNI hostname matches any SAN in a list.
///
/// Returns `true` if at least one SAN in the list matches the SNI hostname
/// according to the rules in [`sni_matches_san`].
///
/// # Examples
///
/// ```
/// use tlapix_analyzer::sni_match::sni_matches_any_san;
///
/// let sans = vec![
///     "www.example.com".to_string(),
///     "*.example.org".to_string(),
/// ];
///
/// assert!(sni_matches_any_san("www.example.com", &sans));
/// assert!(sni_matches_any_san("api.example.org", &sans));
/// assert!(!sni_matches_any_san("other.example.net", &sans));
/// ```
pub fn sni_matches_any_san(sni: &str, sans: &[String]) -> bool {
    sans.iter().any(|san| sni_matches_san(sni, san))
}

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Exact match tests
    // -----------------------------------------------------------------------

    #[test]
    fn exact_match_same_case() {
        assert!(sni_matches_san("www.example.com", "www.example.com"));
    }

    #[test]
    fn exact_match_case_insensitive_sni_upper() {
        assert!(sni_matches_san("WWW.EXAMPLE.COM", "www.example.com"));
    }

    #[test]
    fn exact_match_case_insensitive_san_upper() {
        assert!(sni_matches_san("www.example.com", "WWW.EXAMPLE.COM"));
    }

    #[test]
    fn exact_match_mixed_case() {
        assert!(sni_matches_san("WwW.ExAmPlE.cOm", "wWw.eXaMpLe.CoM"));
    }

    #[test]
    fn exact_match_single_label() {
        assert!(sni_matches_san("localhost", "localhost"));
    }

    #[test]
    fn no_match_different_domains() {
        assert!(!sni_matches_san("www.example.com", "www.other.com"));
    }

    #[test]
    fn no_match_different_subdomains() {
        assert!(!sni_matches_san("api.example.com", "www.example.com"));
    }

    // -----------------------------------------------------------------------
    // Wildcard match tests
    // -----------------------------------------------------------------------

    #[test]
    fn wildcard_single_level_subdomain() {
        assert!(sni_matches_san("www.example.com", "*.example.com"));
    }

    #[test]
    fn wildcard_different_subdomain() {
        assert!(sni_matches_san("api.example.com", "*.example.com"));
    }

    #[test]
    fn wildcard_case_insensitive() {
        assert!(sni_matches_san("WWW.Example.COM", "*.example.com"));
    }

    #[test]
    fn wildcard_no_match_two_levels_deep() {
        assert!(!sni_matches_san("sub.www.example.com", "*.example.com"));
    }

    #[test]
    fn wildcard_no_match_bare_domain() {
        // "example.com" has no subdomain relative to "*.example.com"
        assert!(!sni_matches_san("example.com", "*.example.com"));
    }

    #[test]
    fn wildcard_no_match_different_base_domain() {
        assert!(!sni_matches_san("www.example.com", "*.other.com"));
    }

    #[test]
    fn wildcard_multi_level_base_domain() {
        // *.sub.example.com should match foo.sub.example.com
        assert!(sni_matches_san("foo.sub.example.com", "*.sub.example.com"));
    }

    #[test]
    fn wildcard_multi_level_base_no_match_two_levels() {
        // *.sub.example.com should NOT match bar.foo.sub.example.com
        assert!(!sni_matches_san(
            "bar.foo.sub.example.com",
            "*.sub.example.com"
        ));
    }

    #[test]
    fn wildcard_empty_base_domain_no_match() {
        // "*." with empty base domain should not match anything
        assert!(!sni_matches_san("anything", "*."));
    }

    #[test]
    fn wildcard_does_not_match_itself() {
        // The literal "*.example.com" as an SNI should not match "*.example.com" via wildcard
        // but it does match via exact comparison
        assert!(sni_matches_san("*.example.com", "*.example.com"));
    }

    // -----------------------------------------------------------------------
    // Edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn empty_sni_no_match() {
        assert!(!sni_matches_san("", "www.example.com"));
        assert!(!sni_matches_san("", "*.example.com"));
    }

    #[test]
    fn empty_san_no_match() {
        assert!(!sni_matches_san("www.example.com", ""));
    }

    #[test]
    fn both_empty_match() {
        // Two empty strings are equal
        assert!(sni_matches_san("", ""));
    }

    #[test]
    fn trailing_dot_not_normalized() {
        // FQDN with trailing dot is treated as-is (different from without)
        assert!(!sni_matches_san("www.example.com.", "www.example.com"));
    }

    // -----------------------------------------------------------------------
    // sni_matches_any_san tests
    // -----------------------------------------------------------------------

    #[test]
    fn any_san_exact_match() {
        let sans = vec![
            "api.example.com".to_string(),
            "www.example.com".to_string(),
        ];
        assert!(sni_matches_any_san("www.example.com", &sans));
    }

    #[test]
    fn any_san_wildcard_match() {
        let sans = vec![
            "specific.example.com".to_string(),
            "*.example.org".to_string(),
        ];
        assert!(sni_matches_any_san("anything.example.org", &sans));
    }

    #[test]
    fn any_san_no_match() {
        let sans = vec![
            "www.example.com".to_string(),
            "*.example.org".to_string(),
        ];
        assert!(!sni_matches_any_san("www.other.net", &sans));
    }

    #[test]
    fn any_san_empty_list() {
        let sans: Vec<String> = vec![];
        assert!(!sni_matches_any_san("www.example.com", &sans));
    }

    #[test]
    fn any_san_multiple_wildcards() {
        let sans = vec![
            "*.example.com".to_string(),
            "*.example.org".to_string(),
        ];
        assert!(sni_matches_any_san("www.example.com", &sans));
        assert!(sni_matches_any_san("api.example.org", &sans));
        assert!(!sni_matches_any_san("www.example.net", &sans));
    }

    #[test]
    fn any_san_prefers_first_match() {
        // Both exact and wildcard match — function returns true regardless of which matches
        let sans = vec![
            "www.example.com".to_string(),
            "*.example.com".to_string(),
        ];
        assert!(sni_matches_any_san("www.example.com", &sans));
    }
}
