use std::collections::HashMap;

fn parse_cookie(cookie: &str) -> HashMap<String, String> {
    cookie
        .split('&')
        .filter_map(|f| {

            let key_and_value: Vec<_> = f.split('=').collect();
            if key_and_value.len() == 2 && key_and_value[0] != "" {
                Some((key_and_value[0].to_string(), key_and_value[1].to_string()))
            } else {
                None
            }
        })
        .collect()
}

fn strip_metas(s: &str) -> String {
    s.chars().filter(|x| *x != '=' && *x != '&').collect()
}

fn profile_for(email: &str) -> String {
    return format!("email={}&uid=10&role=user", strip_metas(email));
}

pub fn challenge13() {}

#[test]
fn test() {
    assert!(parse_cookie("a=b&name=hello").contains_key("a"));
    assert!(parse_cookie("a=b&name=hello").contains_key("name"));
    assert_eq!(parse_cookie("a=b&name=hello").len(), 2);
    assert_eq!(parse_cookie("a=b&invalid&name=hello").len(), 2);
    assert_eq!(parse_cookie("a=b&=invalid&name=hello").len(), 2);
    assert_eq!(profile_for("mwright@cygnacom.com"),
               "email=mwright@cygnacom.com&uid=10&role=user");
}
