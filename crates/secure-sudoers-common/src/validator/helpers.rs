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
    // Try processing the whole argument as a single multi-character flag or flag with '='
    if process_flag_with_value(&arg, None, flags_with_args, flags_with_path_args, flag_rules, iter, blocked_paths, out)? {
        return Ok(());
    }
    if flags.contains(&arg) {
        out.push(arg);
        return Ok(());
    }

    // Otherwise, deconstruct into individual short flags with greedy argument consumption
    let chars: Vec<char> = arg[1..].chars().collect();
    for (i, &c) in chars.iter().enumerate() {
        let s = format!("-{}", c);
        let has_rule = flag_rules.contains_key(&s);
        let is_arg_flag = flags_with_args.contains(&s);
        let is_path_flag = flags_with_path_args.contains(&s);

        if has_rule || is_arg_flag || is_path_flag {
            // Greedy consumption: if there are remaining characters, they are the value.
            let attached_value = if i + 1 < chars.len() {
                Some(chars[i + 1..].iter().collect::<String>())
            } else {
                None
            };

            // Process this specific flag (which we know takes a value)
            process_flag_with_value(&s, attached_value, flags_with_args, flags_with_path_args, flag_rules, iter, blocked_paths, out)?;
            return Ok(());
        }

        if !flags.contains(&s) {
            return Err(format!("Flag '{}' (from '{}') is not permitted for tool '{}'", s, arg, tool_name));
        }
        out.push(s);
    }
    Ok(())
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
    if !process_flag_with_value(flag, None, flags_with_args, flags_with_path_args, flag_rules, iter, blocked_paths, out)? {
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
    attached_value: Option<String>,
    flags_with_args: &[String],
    flags_with_path_args: &[String],
    flag_rules: &HashMap<String, FlagRule>,
    iter: &mut Peekable<IntoIter<String>>,
    blocked_paths: &[String],
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

    let has_rule = flag_rules.contains_key(flag_name);
    let is_arg_flag = flags_with_args.contains(&flag_name.to_string());
    let is_path_flag = flags_with_path_args.contains(&flag_name.to_string());

    if has_rule || is_arg_flag || is_path_flag {
        let val = match provided_value {
            Some(v) => v,
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
