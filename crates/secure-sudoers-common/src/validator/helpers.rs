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
) -> Result<(), crate::error::Error> {
    process_any_flag(&flag, params, iter, out)
}

pub fn process_short_flag(
    arg: String,
    params: &ValidationParams<'_>,
    iter: &mut Peekable<IntoIter<String>>,
    out: &mut Vec<ValidatedArg>,
) -> Result<(), crate::error::Error> {
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
            return Err(crate::error::Error::Validation(format!(
                "Flag '{}' is not permitted for tool '{}'",
                display_flag, params.tool_name
            )));
        }
    }
    Ok(())
}

fn process_any_flag(
    flag: &str,
    params: &ValidationParams<'_>,
    iter: &mut Peekable<IntoIter<String>>,
    out: &mut Vec<ValidatedArg>,
) -> Result<(), crate::error::Error> {
    if !process_flag_with_value(flag, None, params, iter, out)? {
        let display_flag = sanitize_unknown_flag_for_error(flag);
        return Err(crate::error::Error::Validation(format!(
            "Flag '{}' is not permitted for tool '{}'",
            display_flag, params.tool_name
        )));
    }
    Ok(())
}

fn sanitize_unknown_flag_for_error(flag: &str) -> &str {
    if let Some((flag_name, _)) = flag.split_once('=') {
        return flag_name;
    }

    if flag.starts_with('-') && !flag.starts_with("--") && flag.chars().count() > 2 {
        return flag
            .char_indices()
            .nth(2)
            .map(|(idx, _)| &flag[..idx])
            .unwrap_or(flag);
    }

    flag
}

fn take_flag_value(
    flag_name: &str,
    provided_value: &mut Option<String>,
    iter: &mut Peekable<IntoIter<String>>,
) -> Result<String, crate::error::Error> {
    if let Some(value) = provided_value.take() {
        return Ok(value);
    }
    iter.next().ok_or_else(|| {
        crate::error::Error::System(format!("Flag '{}' requires an argument", flag_name))
    })
}

fn push_string_flag_value(
    flag_name: &str,
    val: String,
    config: &ParameterConfig,
    params: &ValidationParams<'_>,
    out: &mut Vec<ValidatedArg>,
) -> Result<(), crate::error::Error> {
    let display_val = if config.sensitive { "[REDACTED]" } else { &val };

    if config.is_explicitly_disallowed(&val) {
        return Err(crate::error::Error::Validation(format!(
            "Flag '{}' argument '{}' is explicitly disallowed for tool '{}'",
            flag_name, display_val, params.tool_name
        )));
    }

    if !config.matches_allowed_or_regex(&val) {
        return Err(crate::error::Error::Validation(format!(
            "Flag '{}' argument '{}' is not permitted by policy",
            flag_name, display_val
        )));
    }

    out.push(ValidatedArg::String(flag_name.to_string()));
    out.push(ValidatedArg::String(val));
    Ok(())
}

fn push_path_flag_value(
    flag_name: &str,
    val: String,
    config: &ParameterConfig,
    params: &ValidationParams<'_>,
    out: &mut Vec<ValidatedArg>,
) -> Result<(), crate::error::Error> {
    let secure_path = validate_path_value(
        &val,
        config,
        &ValidationContext::Flag(flag_name.to_string()),
        params.blocked_paths,
        |path, is_sensitive| {
            let display_val = if is_sensitive {
                "[REDACTED]"
            } else {
                val.as_str()
            };
            if is_sensitive {
                format!(
                    "Flag '{}' argument '{}' is explicitly disallowed for tool '{}'",
                    flag_name, display_val, params.tool_name
                )
            } else {
                format!(
                    "Flag '{}' argument '{}' is explicitly disallowed for tool '{}' (resolved to canonical path '{}')",
                    flag_name, display_val, params.tool_name, path
                )
            }
        },
        |path, is_sensitive| {
            let display_path = if is_sensitive { "[REDACTED]" } else { path };
            format!(
                "Flag '{}' canonical path '{}' is not permitted by policy",
                flag_name, display_path
            )
        },
    )?;

    out.push(ValidatedArg::String(flag_name.to_string()));
    out.push(ValidatedArg::Path(secure_path));
    Ok(())
}

fn validate_path_value<FDisallowed, FPolicy>(
    raw_value: &str,
    config: &ParameterConfig,
    context: &ValidationContext,
    blocked_paths: &[String],
    disallowed_msg: FDisallowed,
    policy_msg: FPolicy,
) -> Result<crate::models::SecurePath, crate::error::Error>
where
    FDisallowed: Fn(&str, bool) -> String,
    FPolicy: Fn(&str, bool) -> String,
{
    let secure_path = check_path(raw_value, context, blocked_paths).map_err(|e| {
        crate::error::Error::Validation(if config.sensitive {
            "Access to a sensitive path was denied".to_string()
        } else {
            e.to_string()
        })
    })?;

    if config.is_explicitly_disallowed(&secure_path.path) {
        return Err(crate::error::Error::Validation(disallowed_msg(
            &secure_path.path,
            config.sensitive,
        )));
    }

    if !config.matches_allowed_or_regex(&secure_path.path) {
        return Err(crate::error::Error::Config(policy_msg(
            &secure_path.path,
            config.sensitive,
        )));
    }

    Ok(secure_path)
}

fn process_flag_with_value(
    flag: &str,
    attached_value: Option<String>,
    params: &ValidationParams<'_>,
    iter: &mut Peekable<IntoIter<String>>,
    out: &mut Vec<ValidatedArg>,
) -> Result<bool, crate::error::Error> {
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
                    return Err(crate::error::Error::System(format!(
                        "Flag '{}' does not take an argument",
                        flag_name
                    )));
                }
                out.push(ValidatedArg::String(flag_name.to_string()));
                Ok(true)
            }
            ParameterType::String => {
                let mut provided_value = provided_value;
                let val = take_flag_value(flag_name, &mut provided_value, iter)?;
                push_string_flag_value(flag_name, val, config, params, out)?;
                Ok(true)
            }
            ParameterType::Path => {
                let mut provided_value = provided_value;
                let val = take_flag_value(flag_name, &mut provided_value, iter)?;
                push_path_flag_value(flag_name, val, config, params, out)?;
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
    pub safe_re: &'a Regex,
    pub config: &'a Option<ParameterConfig>,
    pub blocked_paths: &'a [String],
}

pub fn push_positional(
    arg: String,
    params: &PositionalParams<'_>,
    out: &mut Vec<ValidatedArg>,
) -> Result<(), crate::error::Error> {
    let is_path = params
        .config
        .as_ref()
        .is_some_and(|c| c.param_type == ParameterType::Path);
    let is_sensitive = params.config.as_ref().is_some_and(|c| c.sensitive);
    let display_arg = if is_sensitive { "[REDACTED]" } else { &arg };
    if !params.safe_re.is_match(&arg) {
        return Err(crate::error::Error::System(format!(
            "Positional argument '{}' contains illegal characters",
            display_arg
        )));
    }

    if is_path {
        let config = params.config.as_ref().unwrap();
        let secure_path = validate_path_value(
            &arg,
            config,
            params.context,
            params.blocked_paths,
            |path, is_sensitive| {
                if is_sensitive {
                    format!(
                        "Positional argument '{}' is explicitly disallowed for tool '{}'",
                        display_arg, params.tool_name
                    )
                } else {
                    format!(
                        "Positional argument '{}' is explicitly disallowed for tool '{}' (resolved to canonical path '{}')",
                        display_arg, params.tool_name, path
                    )
                }
            },
            |path, is_sensitive| {
                let display_path = if is_sensitive { "[REDACTED]" } else { path };
                format!(
                    "Positional argument canonical path '{}' is not permitted by policy",
                    display_path
                )
            },
        )?;
        out.push(ValidatedArg::Path(secure_path));
        return Ok(());
    }

    if let Some(config) = params.config {
        if config.is_explicitly_disallowed(&arg) {
            return Err(crate::error::Error::Validation(format!(
                "Positional argument '{}' is explicitly disallowed for tool '{}'",
                display_arg, params.tool_name
            )));
        }
        if !config.matches_allowed_or_regex(&arg) {
            return Err(crate::error::Error::Validation(format!(
                "Positional argument '{}' is not permitted by policy",
                display_arg
            )));
        }
    }

    if arg.starts_with('-') && arg.len() > 1 {
        return Err(crate::error::Error::Security(format!(
            "Security failure: illegal flag-like positional argument '{}' in '{}' context",
            arg, params.context
        )));
    }
    out.push(ValidatedArg::String(arg));
    Ok(())
}
