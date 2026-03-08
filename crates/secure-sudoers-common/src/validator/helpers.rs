use crate::models::{FlagRule, ValidationContext};
use crate::fs::check_path;
use regex::Regex;
use std::collections::HashMap;
use std::iter::Peekable;
use std::vec::IntoIter;

pub fn process_long_flag(
    flag: String,
    tool_name: &str,
    flags: &[String],
    flags_with_args: &[String],
    flags_with_path_args: &[String],
    flag_rules: &HashMap<String, FlagRule>,
    iter: &mut Peekable<IntoIter<String>>,
    blocked_paths: &[String],
    out: &mut Vec<String>,
) -> Result<(), String> {
    process_any_flag(&flag, tool_name, flags, flags_with_args, flags_with_path_args, flag_rules, iter, blocked_paths, out)
}

pub fn process_short_flag(
    arg: String,
    tool_name: &str,
    flags: &[String],
    flags_with_args: &[String],
    flags_with_path_args: &[String],
    flag_rules: &HashMap<String, FlagRule>,
    iter: &mut Peekable<IntoIter<String>>,
    blocked_paths: &[String],
    out: &mut Vec<String>,
) -> Result<(), String> {
    let chars: Vec<char> = arg[1..].chars().collect();
    if chars.len() > 1 {
        // Try processing the whole cluster as a single multi-character flag first (e.g. -tt)
        if process_flag_with_value(&arg, flags_with_args, flags_with_path_args, flag_rules, iter, blocked_paths, out)? {
            return Ok(());
        }
        if flags.contains(&arg) {
            out.push(arg);
            return Ok(());
        }

        // Otherwise, deconstruct into individual short flags
        for c in &chars {
            let s = format!("-{}", c);
            if flags_with_args.contains(&s) || flags_with_path_args.contains(&s) || flag_rules.contains_key(&s) {
                return Err(format!("Flag '{}' takes an argument and cannot be clustered in '{}'", s, arg));
            }
            if !flags.contains(&s) {
                return Err(format!("Flag '{}' (from '{}') is not permitted for tool '{}'", s, arg, tool_name));
            }
        }
        for c in chars { out.push(format!("-{}", c)); }
        Ok(())
    } else {
        process_any_flag(&arg, tool_name, flags, flags_with_args, flags_with_path_args, flag_rules, iter, blocked_paths, out)
    }
}

fn process_any_flag(
    flag: &str,
    tool_name: &str,
    flags: &[String],
    flags_with_args: &[String],
    flags_with_path_args: &[String],
    flag_rules: &HashMap<String, FlagRule>,
    iter: &mut Peekable<IntoIter<String>>,
    blocked_paths: &[String],
    out: &mut Vec<String>,
) -> Result<(), String> {
    if !process_flag_with_value(flag, flags_with_args, flags_with_path_args, flag_rules, iter, blocked_paths, out)? {
        if flags.contains(&flag.to_string()) {
            out.push(flag.to_string());
        } else {
            return Err(format!("Flag '{}' is not permitted for tool '{}'", flag, tool_name));
        }
    }
    Ok(())
}

fn process_flag_with_value(
    flag: &str,
    flags_with_args: &[String],
    flags_with_path_args: &[String],
    flag_rules: &HashMap<String, FlagRule>,
    iter: &mut Peekable<IntoIter<String>>,
    blocked_paths: &[String],
    out: &mut Vec<String>,
) -> Result<bool, String> {
    let (flag_name, provided_value) = match flag.find('=') {
        Some(idx) => (&flag[..idx], Some(&flag[idx + 1..])),
        None => (flag, None),
    };

    let has_rule = flag_rules.contains_key(flag_name);
    let is_arg_flag = flags_with_args.contains(&flag_name.to_string());
    let is_path_flag = flags_with_path_args.contains(&flag_name.to_string());

    if has_rule || is_arg_flag || is_path_flag {
        let val = match provided_value {
            Some(v) => v.to_string(),
            None => iter.next().ok_or_else(|| format!("Flag '{}' requires an argument", flag_name))?,
        };
        
        if let Some(rule) = flag_rules.get(flag_name) {
            if !rule.matches(&val) {
                return Err(format!("Flag '{}' argument '{}' is not permitted by policy", flag_name, val));
            }
        }

        if is_path_flag {
            let context = ValidationContext::Flag(flag_name.to_string());
            let canonical = check_path(&val, &context, blocked_paths)?;
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

pub fn push_positional(
    arg: String,
    tool_name: &str,
    context: &ValidationContext,
    disallowed: &[String],
    safe_re: &Regex,
    validate_as_path: bool,
    blocked_paths: &[String],
    out: &mut Vec<String>,
) -> Result<(), String> {
    if disallowed.contains(&arg) {
        return Err(format!("Positional argument '{}' is explicitly disallowed for tool '{}'", arg, tool_name));
    }
    if !safe_re.is_match(&arg) {
        return Err(format!("Positional argument '{}' contains illegal characters", arg));
    }
    if arg.starts_with('-') && arg.len() > 1 && !validate_as_path {
        return Err(format!("Security failure: illegal flag-like positional argument '{}' in '{}' context", arg, context));
    }

    if validate_as_path {
        let canonical = check_path(&arg, context, blocked_paths)?;
        out.push(canonical);
    } else {
        out.push(arg);
    }
    Ok(())
}
