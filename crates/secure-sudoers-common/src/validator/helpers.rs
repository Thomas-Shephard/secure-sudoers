use crate::fs::check_path;
use crate::models::{FlagRule, ValidationContext};
use regex::Regex;
use std::collections::HashMap;
use std::iter::Peekable;
use std::vec::IntoIter;

pub struct ValidationParams<'a> {
    pub tool_name: &'a str,
    pub flags: &'a [String],
    pub flags_with_args: &'a [String],
    pub flags_with_path_args: &'a [String],
    pub flag_rules: &'a HashMap<String, FlagRule>,
    pub blocked_paths: &'a [String],
    pub sensitive_flags: &'a [String],
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
    if params.flags.contains(&arg) {
        out.push(arg);
        return Ok(());
    }

    let chars: Vec<char> = arg[1..].chars().collect();
    for (i, &c) in chars.iter().enumerate() {
        let s = format!("-{}", c);
        let has_rule = params.flag_rules.contains_key(&s);
        let is_arg_flag = params.flags_with_args.contains(&s);
        let is_path_flag = params.flags_with_path_args.contains(&s);

        if has_rule || is_arg_flag || is_path_flag {
            let attached_value = if i + 1 < chars.len() {
                Some(chars[i + 1..].iter().collect::<String>())
            } else {
                None
            };

            process_flag_with_value(&s, attached_value, params, iter, out)?;
            return Ok(());
        }

        if !params.flags.contains(&s) {
            return Err(format!(
                "Flag '{}' (from '{}') is not permitted for tool '{}'",
                s, arg, params.tool_name
            ));
        }
        out.push(s);
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
        if params.flags.contains(&flag.to_string()) {
            out.push(flag.to_string());
        } else {
            return Err(format!(
                "Flag '{}' is not permitted for tool '{}'",
                flag, params.tool_name
            ));
        }
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

    let has_rule = params.flag_rules.contains_key(flag_name);
    let is_arg_flag = params.flags_with_args.contains(&flag_name.to_string());
    let is_path_flag = params.flags_with_path_args.contains(&flag_name.to_string());

    if has_rule || is_arg_flag || is_path_flag {
        let val = match provided_value {
            Some(v) => v,
            None => iter
                .next()
                .ok_or_else(|| format!("Flag '{}' requires an argument", flag_name))?,
        };

        if params
            .flag_rules
            .get(flag_name)
            .is_some_and(|rule| !rule.matches(&val))
        {
            let display_val = if params.sensitive_flags.iter().any(|f| f == flag_name) {
                "[REDACTED]"
            } else {
                &val
            };

            return Err(format!(
                "Flag '{}' argument '{}' is not permitted by policy",
                flag_name, display_val
            ));
        }

        if is_path_flag {
            let context = ValidationContext::Flag(flag_name.to_string());
            let canonical = check_path(&val, &context, params.blocked_paths)?;
            out.push(flag_name.to_string());
            out.push(canonical);
        } else {
            out.push(flag_name.to_string());
            out.push(val);
        }
        return Ok(true);
    }
    Ok(false)
}

pub struct PositionalParams<'a> {
    pub tool_name: &'a str,
    pub context: &'a ValidationContext,
    pub disallowed: &'a [String],
    pub safe_re: &'a Regex,
    pub validate_as_path: bool,
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
    if arg.starts_with('-') && arg.len() > 1 && !params.validate_as_path {
        return Err(format!(
            "Security failure: illegal flag-like positional argument '{}' in '{}' context",
            arg, params.context
        ));
    }

    if params.validate_as_path {
        let canonical = check_path(&arg, params.context, params.blocked_paths)?;
        out.push(canonical);
    } else {
        out.push(arg);
    }
    Ok(())
}
