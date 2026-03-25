use crate::fs::check_path;
use crate::models::{ParameterConfig, ParameterType, ValidationContext};
use crate::validator::ValidatedArg;
use regex::Regex;
use std::collections::HashMap;
use std::iter::Peekable;
use std::vec::IntoIter;

pub struct ValidationParams<'a> {
    pub tool_name: &'a str,
    pub parameters: &'a HashMap<String, ParameterConfig>,
    pub blocked_paths: &'a [String],
}

pub fn process_long_flag(
    flag: String,
    params: &ValidationParams<'_>,
    iter: &mut Peekable<IntoIter<String>>,
    out: &mut Vec<ValidatedArg>,
) -> Result<(), String> {
    process_any_flag(&flag, params, iter, out)
}

pub fn process_short_flag(
    arg: String,
    params: &ValidationParams<'_>,
    iter: &mut Peekable<IntoIter<String>>,
    out: &mut Vec<ValidatedArg>,
) -> Result<(), String> {
    if process_flag_with_value(&arg, None, params, iter, out)? {
        return Ok(());
    }

    let chars: Vec<char> = arg[1..].chars().collect();
    for (i, &c) in chars.iter().enumerate() {
        let s = format!("-{}", c);
        if let Some(config) = params.parameters.get(&s) {
            if config.param_type != ParameterType::Bool {
                let attached_value = if i + 1 < chars.len() {
                    Some(chars[i + 1..].iter().collect::<String>())
                } else {
                    None
                };

                process_flag_with_value(&s, attached_value, params, iter, out)?;
                return Ok(());
            }
            out.push(ValidatedArg::String(s));
        } else {
            let display_flag = sanitize_unknown_flag_for_error(&s);
            return Err(format!(
                "Flag '{}' is not permitted for tool '{}'",
                display_flag, params.tool_name
            ));
        }
    }
    Ok(())
}

fn process_any_flag(
    flag: &str,
    params: &ValidationParams<'_>,
    iter: &mut Peekable<IntoIter<String>>,
    out: &mut Vec<ValidatedArg>,
) -> Result<(), String> {
    if !process_flag_with_value(flag, None, params, iter, out)? {
        let display_flag = sanitize_unknown_flag_for_error(flag);
        return Err(format!(
            "Flag '{}' is not permitted for tool '{}'",
            display_flag, params.tool_name
        ));
    }
    Ok(())
}

fn sanitize_unknown_flag_for_error(flag: &str) -> &str {
    if let Some((flag_name, _)) = flag.split_once('=') {
        return flag_name;
    }

    if flag.starts_with('-') && !flag.starts_with("--") && flag.len() > 2 {
        return &flag[..2];
    }

    flag
}

fn process_flag_with_value(
    flag: &str,
    attached_value: Option<String>,
    params: &ValidationParams<'_>,
    iter: &mut Peekable<IntoIter<String>>,
    out: &mut Vec<ValidatedArg>,
) -> Result<bool, String> {
    let (flag_name, provided_value) = if let Some(val) = attached_value {
        (flag, Some(val))
    } else {
        match flag.find('=') {
            Some(idx) => (&flag[..idx], Some(flag[idx + 1..].to_string())),
            None => (flag, None),
        }
    };

    if let Some(config) = params.parameters.get(flag_name) {
        match config.param_type {
            ParameterType::Bool => {
                if provided_value.is_some() {
                    return Err(format!("Flag '{}' does not take an argument", flag_name));
                }
                out.push(ValidatedArg::String(flag_name.to_string()));
                Ok(true)
            }
            ParameterType::String | ParameterType::Path => {
                let val = match provided_value {
                    Some(v) => v,
                    None => iter
                        .next()
                        .ok_or_else(|| format!("Flag '{}' requires an argument", flag_name))?,
                };

                let is_path = config.param_type == ParameterType::Path;

                if !is_path && !config.matches(&val) {
                    let display_val = if config.sensitive { "[REDACTED]" } else { &val };
                    return Err(format!(
                        "Flag '{}' argument '{}' is not permitted by policy",
                        flag_name, display_val
                    ));
                }

                if is_path {
                    let context = ValidationContext::Flag(flag_name.to_string());
                    let secure_path =
                        check_path(&val, &context, params.blocked_paths).map_err(|e| {
                            if config.sensitive {
                                "Access to a sensitive path was denied".to_string()
                            } else {
                                e
                            }
                        })?;
                    // Re-check regex against canonical path if it exists
                    if !config.matches(&secure_path.path) {
                        let display_path = if config.sensitive {
                            "[REDACTED]"
                        } else {
                            &secure_path.path
                        };
                        return Err(format!(
                            "Flag '{}' canonical path '{}' is not permitted by policy regex",
                            flag_name, display_path
                        ));
                    }
                    out.push(ValidatedArg::String(flag_name.to_string()));
                    out.push(ValidatedArg::Path(secure_path));
                } else {
                    out.push(ValidatedArg::String(flag_name.to_string()));
                    out.push(ValidatedArg::String(val));
                }
                Ok(true)
            }
        }
    } else {
        Ok(false)
    }
}

pub struct PositionalParams<'a> {
    pub tool_name: &'a str,
    pub context: &'a ValidationContext,
    pub disallowed: &'a [String],
    pub safe_re: &'a Regex,
    pub config: &'a Option<ParameterConfig>,
    pub blocked_paths: &'a [String],
}

pub fn push_positional(
    arg: String,
    params: &PositionalParams<'_>,
    out: &mut Vec<ValidatedArg>,
) -> Result<(), String> {
    if params.disallowed.contains(&arg) {
        return Err(format!(
            "Positional argument '{}' is explicitly disallowed for tool '{}'",
            arg, params.tool_name
        ));
    }
    if !params.safe_re.is_match(&arg) {
        let is_sensitive = params.config.as_ref().map(|c| c.sensitive).unwrap_or(false);
        let display_val = if is_sensitive { "[REDACTED]" } else { &arg };
        return Err(format!(
            "Positional argument '{}' contains illegal characters",
            display_val
        ));
    }

    if let Some(config) = params.config {
        let is_path = config.param_type == ParameterType::Path;
        if !is_path && !config.matches(&arg) {
            let display_val = if config.sensitive { "[REDACTED]" } else { &arg };
            return Err(format!(
                "Positional argument '{}' is not permitted by policy",
                display_val
            ));
        }
    }

    let is_path = params
        .config
        .as_ref()
        .is_some_and(|c| c.param_type == ParameterType::Path);

    if is_path {
        let config = params.config.as_ref().unwrap();
        let is_sensitive = config.sensitive;
        let secure_path = check_path(&arg, params.context, params.blocked_paths).map_err(|e| {
            if is_sensitive {
                "Access to a sensitive path was denied".to_string()
            } else {
                e
            }
        })?;
        if !config.matches(&secure_path.path) {
            let display_path = if is_sensitive {
                "[REDACTED]"
            } else {
                &secure_path.path
            };
            return Err(format!(
                "Positional argument canonical path '{}' is not permitted by policy regex",
                display_path
            ));
        }
        out.push(ValidatedArg::Path(secure_path));
    } else {
        if arg.starts_with('-') && arg.len() > 1 {
            return Err(format!(
                "Security failure: illegal flag-like positional argument '{}' in '{}' context",
                arg, params.context
            ));
        }
        out.push(ValidatedArg::String(arg));
    }
    Ok(())
}
