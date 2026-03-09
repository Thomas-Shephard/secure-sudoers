use crate::fs::check_path;
use crate::models::{ParameterConfig, ParameterType, ValidationContext};
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
    out: &mut Vec<String>,
) -> Result<(), String> {
    process_any_flag(&flag, params, iter, out)
}

pub fn process_short_flag(
    arg: String,
    params: &ValidationParams<'_>,
    iter: &mut Peekable<IntoIter<String>>,
    out: &mut Vec<String>,
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
            out.push(s);
        } else {
            return Err(format!(
                "Flag '{}' (from '{}') is not permitted for tool '{}'",
                s, arg, params.tool_name
            ));
        }
    }
    Ok(())
}

fn process_any_flag(
    flag: &str,
    params: &ValidationParams<'_>,
    iter: &mut Peekable<IntoIter<String>>,
    out: &mut Vec<String>,
) -> Result<(), String> {
    if !process_flag_with_value(flag, None, params, iter, out)? {
        return Err(format!(
            "Flag '{}' is not permitted for tool '{}'",
            flag, params.tool_name
        ));
    }
    Ok(())
}

fn process_flag_with_value(
    flag: &str,
    attached_value: Option<String>,
    params: &ValidationParams<'_>,
    iter: &mut Peekable<IntoIter<String>>,
    out: &mut Vec<String>,
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
                out.push(flag_name.to_string());
                Ok(true)
            }
            ParameterType::String | ParameterType::Path => {
                let val = match provided_value {
                    Some(v) => v,
                    None => iter
                        .next()
                        .ok_or_else(|| format!("Flag '{}' requires an argument", flag_name))?,
                };

                if !config.matches(&val) {
                    let display_val = if config.sensitive { "[REDACTED]" } else { &val };
                    return Err(format!(
                        "Flag '{}' argument '{}' is not permitted by policy",
                        flag_name, display_val
                    ));
                }

                if config.param_type == ParameterType::Path {
                    let context = ValidationContext::Flag(flag_name.to_string());
                    let canonical = check_path(&val, &context, params.blocked_paths)?;
                    // Re-check regex against canonical path if it exists
                    if !config.matches(&canonical) {
                        return Err(format!(
                            "Flag '{}' canonical path '{}' is not permitted by policy regex",
                            flag_name, canonical
                        ));
                    }
                    out.push(flag_name.to_string());
                    out.push(canonical);
                } else {
                    out.push(flag_name.to_string());
                    out.push(val);
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
    out: &mut Vec<String>,
) -> Result<(), String> {
    if params.disallowed.contains(&arg) {
        return Err(format!(
            "Positional argument '{}' is explicitly disallowed for tool '{}'",
            arg, params.tool_name
        ));
    }
    if !params.safe_re.is_match(&arg) {
        return Err(format!(
            "Positional argument '{}' contains illegal characters",
            arg
        ));
    }

    if let Some(config) = params.config {
        if !config.matches(&arg) {
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
        let canonical = check_path(&arg, params.context, params.blocked_paths)?;
        if !config.matches(&canonical) {
            return Err(format!(
                "Positional argument canonical path '{}' is not permitted by policy regex",
                canonical
            ));
        }
        out.push(canonical);
    } else {
        if arg.starts_with('-') && arg.len() > 1 {
            return Err(format!(
                "Security failure: illegal flag-like positional argument '{}' in '{}' context",
                arg, params.context
            ));
        }
        out.push(arg);
    }
    Ok(())
}
