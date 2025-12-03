use std::collections::HashMap;
use std::error::Error;
use std::iter::Peekable;
use std::str::Chars;

use crate::treepp::*;
use bitcoin::{Opcode, Witness};

use bitcoin::opcodes::all::*;
use bitcoin::{hashes::Hash, ScriptBuf, TapLeafHash, Transaction};
use bitcoin_scriptexec::{Exec, ExecCtx, TxTemplate};

use bitcoin::script::{Instruction, PushBytesBuf};
use bitcoin_script::builder::StructuredScript;

use once_cell::sync::Lazy;

pub fn roll_constant(d: usize) -> Script {
    script! {
        if d == 0 {

        } else if d == 1 {
            OP_SWAP
        } else if d == 2 {
            OP_ROT
        } else {
            { d } OP_ROLL
        }
    }
}

pub fn extend_witness(w: &mut Witness, add: Witness) {
    for x in &add {
        w.push(x)
    }
}

pub fn does_unlock(script: Vec<u8>, witness: Vec<Vec<u8>>) -> bool {
    let mut exec = Exec::new(
        ExecCtx::Tapscript,
        Default::default(),
        TxTemplate {
            tx: Transaction {
                version: bitcoin::transaction::Version::TWO,
                lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
                input: vec![],
                output: vec![],
            },
            prevouts: vec![],
            input_idx: 0,
            taproot_annex_scriptleaf: Some((TapLeafHash::all_zeros(), None)),
        },
        ScriptBuf::from_bytes(script),
        witness,
    )
    .expect("error creating exec");
    loop {
        if exec.exec_next().is_err() {
            break;
        }
    }
    exec.result().unwrap().success
}

pub fn does_raise_error(script: Vec<u8>, witness: Vec<Vec<u8>>) -> bool {
    let mut exec = Exec::new(
        ExecCtx::Tapscript,
        Default::default(),
        TxTemplate {
            tx: Transaction {
                version: bitcoin::transaction::Version::TWO,
                lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
                input: vec![],
                output: vec![],
            },
            prevouts: vec![],
            input_idx: 0,
            taproot_annex_scriptleaf: Some((TapLeafHash::all_zeros(), None)),
        },
        ScriptBuf::from_bytes(script),
        witness,
    )
    .expect("error creating exec");
    loop {
        if exec.exec_next().is_err() {
            break;
        }
    }
    exec.result().unwrap().error.is_some()
}

pub fn extract_pushed_data_from_script(
    script: StructuredScript,
) -> Result<Vec<Vec<u8>>, Box<dyn Error>> {
    let compiled_script = script.compile();
    compiled_script
        .instructions()
        .map(|ins_res| match ins_res {
            Ok(Instruction::PushBytes(bytes)) => Ok(bytes.as_bytes().to_vec()),

            Ok(Instruction::Op(op)) => {
                match op {
                    // 0, already captured with PushBytes, left for consistency
                    OP_PUSHBYTES_0 => Ok(vec![]),

                    // 1..=16
                    op_code
                        if op_code.to_u8() >= OP_PUSHNUM_1.to_u8()
                            && op_code.to_u8() <= OP_PUSHNUM_16.to_u8() =>
                    {
                        let val = op_code.to_u8() - 0x50;
                        Ok(vec![val])
                    }

                    // -1
                    OP_PUSHNUM_NEG1 => Ok(vec![0x81]),

                    unexpected_op => Err(format!(
                        "Unexpected Opcode encountered in disprove_script \
                     Expected a data push, but found opcode: {:?}\n in script: {:?}",
                        unexpected_op, compiled_script
                    )),
                }
            }
            Err(e) => Err(format!(
                "Failed to parse disprove script, returned with error: {:?}\n for script: {:?}",
                e, compiled_script
            )),
        })
        .collect::<Result<Vec<_>, String>>()
        .map_err(|s| s.into())
}

static SORTED_OPCODE_NAMES: Lazy<Vec<(String, u8)>> = Lazy::new(|| {
    let mut opcodes: Vec<(String, u8)> = (0u8..=255)
        .map(|x| {
            let s = if x == 0 {
                "OP_0".to_string()
            } else {
                let op = Opcode::from(x);
                format!("{}", op)
            };
            (s, x)
        })
        .collect();
    opcodes.sort_by_key(|(s, _)| s.clone());
    opcodes
});

fn find_opcode(name: String) -> u8 {
    let index = SORTED_OPCODE_NAMES.binary_search_by_key(&name.as_str(), |(s, _)| s.as_str());
    if index.is_err() {
        panic!("OPCODE {} not found:", name);
    }
    SORTED_OPCODE_NAMES[index.unwrap()].1
}

const SEPERATORS: [char; 8] = [',', '(', ')', '{', '}', '[', ']', ':']; //And whitespace

// Doesn't do string (in double quotes) parsing (splits it into several tokens)
fn next_token(iter: &mut Peekable<Chars<'_>>) -> String {
    while let Some(&c) = iter.peek() {
        if c.is_whitespace() {
            iter.next();
        } else {
            break;
        }
    }

    let mut res = String::new();
    let first_char_option = iter.next();
    if first_char_option.is_none() {
        return res;
    }
    let first_char = first_char_option.unwrap();
    res.push(first_char);

    if !SEPERATORS.contains(&first_char) {
        while let Some(&c) = iter.peek() {
            if c.is_whitespace() || SEPERATORS.contains(&c) {
                break;
            }
            res.push(c);
            iter.next();
        }
    }

    res
}

fn argument_list(iter: &mut Peekable<Chars<'_>>) -> String {
    let start_char = *iter.peek().unwrap_or(&'*');
    if start_char != '(' {
        panic!(
            "Argument list doesn't start with a paranthesis: {} {:?}",
            start_char, iter
        );
    }
    iter.next();

    let mut open_paranthesis_count = 0i32;
    iter.take_while(|c| {
        if *c == '(' {
            open_paranthesis_count += 1;
        } else if *c == ')' {
            open_paranthesis_count -= 1;
            if open_paranthesis_count == -1 {
                return false;
            }
        }
        true
    })
    .collect()
}

fn parse_scriptbuf_debug_to_bytes(debug_output: String) -> Vec<u8> {
    let mut script = ScriptBuf::new();
    let mut iter = debug_output.chars().peekable();

    let first_word = next_token(&mut iter);
    let paranthese = next_token(&mut iter);
    if first_word != "Script" || paranthese != "(" {
        panic!(
            "Invalid ScriptBuf format starting with {}{}: {}",
            first_word, paranthese, debug_output
        );
    }

    loop {
        let token = next_token(&mut iter);
        if token == ")" {
            break;
        }

        let opcode_id = find_opcode(token);
        let opcode = Opcode::from(opcode_id);

        if (1..=78).contains(&opcode_id) {
            //OP_PUSHDATA_x or OP_PUSHBYTES_x
            let number_str = next_token(&mut iter);
            let number = number_str.as_bytes();
            let len = number.len();

            if len % 2 != 0 {
                panic!("Invalid number, has odd length: {}", number_str);
            }

            let mut pushed_data = PushBytesBuf::new();
            for i in (0usize..len).step_by(2) {
                let mut str = String::new();
                str.push(char::from(number[i]));
                str.push(char::from(number[i + 1]));
                let parsed_value = u8::from_str_radix(&str.to_string(), 16);
                if parsed_value.is_err() {
                    panic!(
                        "Invalid number conversion at: {} {:?}",
                        str,
                        parsed_value.err()
                    );
                }
                let data_push_error = pushed_data.push(parsed_value.unwrap());
                if data_push_error.is_err() {
                    panic!(
                        "Panicked while pushing data: {:?} {:?} {}",
                        data_push_error.err(),
                        pushed_data,
                        str
                    );
                }
            }
            script.push_slice(pushed_data);
        } else {
            script.push_opcode(opcode);
        }
    }

    let token = next_token(&mut iter);
    if token != "" {
        panic!(
            "Invalid ScriptBuf format, doesn't end in Script() scope: {} {}",
            token, debug_output
        );
    }

    script.to_bytes()
}

//Assumes every script in script_map is looked up
pub fn parse_structuredscript_debug_to_bytes(debug_output: String) -> Vec<u8> {
    let mut iter = debug_output.chars().peekable();

    pub enum SimplifiedStructuredScriptBlock {
        CompiledScript(Vec<u8>),
        PointedScriptIndex(usize),
    }
    let mut subscripts: Vec<Vec<SimplifiedStructuredScriptBlock>> = vec![];
    let mut script_map_lookup: Vec<HashMap<u64, usize>> = vec![];

    let mut st = vec![]; //stack, holding the parents and itself of the current token
    let mut first = true;
    st.push(0);
    subscripts.push(vec![]);
    script_map_lookup.push(HashMap::new());

    while !st.is_empty() {
        let mut token = next_token(&mut iter);
        if !first {
            if token == "}" {
                // End of hashmap
                let double_closing = next_token(&mut iter);
                if double_closing != "}" {
                    panic!(
                        "Structured script doesn't close properly in the end: {}",
                        double_closing
                    );
                }
                st.pop();
                continue;
            } else if token == "," {
                // Inside hashmap
                continue;
            }

            let hash_value = u64::from_str_radix(&token.to_string(), 10).unwrap_or_else(|e| {
                panic!("Invalid hashmap value at map: {} {} {:?}", token, e, iter);
            });
            let hashmap_colon = next_token(&mut iter);
            token = next_token(&mut iter);
            if hashmap_colon != ":" {
                panic!("Hashmap mapping isn't done with colons: {}", hashmap_colon);
            }

            let parent_id = *st.last().unwrap();
            let my_id = *script_map_lookup[parent_id]
                .get(&hash_value)
                .expect(&format!(
                    "hashmap_value not found: {:?} {}",
                    script_map_lookup[parent_id], hash_value
                ));
            st.push(my_id);
        } else {
            // Start
            first = false;
        }

        let id = *st.last().unwrap();
        if token != "StructuredScript" {
            panic!("Script doesn't start with the right name: {}", token);
        }

        while token != "blocks" {
            token = next_token(&mut iter);
        }
        let colon = next_token(&mut iter);
        let starting_square_brackets = next_token(&mut iter);
        if colon != ":" || starting_square_brackets != "[" {
            panic!(
                "Invalid format in blocks start: {} {}",
                colon, starting_square_brackets
            );
        }
        token = next_token(&mut iter);
        while token != "]" {
            if token == "," {
                token = next_token(&mut iter);
                continue;
            }

            let value = argument_list(&mut iter);
            if token == "Script" {
                subscripts[id].push(SimplifiedStructuredScriptBlock::CompiledScript(
                    parse_scriptbuf_debug_to_bytes(value),
                ));
            } else if token == "Call" {
                let hash_value = u64::from_str_radix(&value.to_string(), 10).unwrap_or_else(|e| {
                    panic!("Invalid hashmap value at Call: {} {}", value, e);
                });

                if !script_map_lookup[id].contains_key(&hash_value) {
                    script_map_lookup[id].insert(hash_value, subscripts.len());
                    subscripts.push(vec![]);
                    script_map_lookup.push(HashMap::new());
                }

                subscripts[id].push(SimplifiedStructuredScriptBlock::PointedScriptIndex(
                    *script_map_lookup[id].get(&hash_value).unwrap(),
                ));
            } else {
                panic!("Invalid block name: {}", token);
            }
            token = next_token(&mut iter);
        }

        let comma = next_token(&mut iter);
        if comma != "," {
            panic!("Invalid seperator between blocks and script_map: {}", comma);
        }

        token = next_token(&mut iter);
        let script_map_opening_0: String = next_token(&mut iter);
        let script_map_opening_1: String = next_token(&mut iter);
        if token != "script_map" || script_map_opening_0 != ":" || script_map_opening_1 != "{" {
            panic!(
                "Couldn't find script_map after blocks: {}{}{}",
                token, script_map_opening_0, script_map_opening_1
            );
        }
    }

    let mut result = Vec::<u8>::new();

    let mut execution_stack: Vec<(usize, usize)> = vec![];
    execution_stack.push((0, 0));
    while !execution_stack.is_empty() {
        let (i, j) = execution_stack.pop().unwrap();
        if j + 1 < subscripts[i].len() {
            execution_stack.push((i, j + 1));
        }
        match &subscripts[i][j] {
            SimplifiedStructuredScriptBlock::CompiledScript(s) => {
                result.extend_from_slice(s);
            }
            SimplifiedStructuredScriptBlock::PointedScriptIndex(k) => {
                execution_stack.push((*k, 0));
            }
        }
    }

    result
}

mod tests {
    use super::*;
    use bitcoin::script::{Builder, PushBytes};
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn test_extract_pushed_data_from_script() {
        let mut rng = ChaCha20Rng::seed_from_u64(38);
        let mut test_scripts = vec![];
        let mut values = vec![];
        for i in -512..=512 {
            let script = Builder::new().push_int(i).into_script();
            values.push(script.clone());
            test_scripts.push(script! {
                { i }
            });
        }

        for _ in 0..128 {
            let value = rng.gen::<i32>();
            let script = Builder::new().push_int(value as i64).into_script();
            values.push(script.clone());
            test_scripts.push(script! {
                { value }
            })
        }

        for i in 1..=128 {
            let v = (0..(rng.gen_range(1..=i)))
                .map(|_| rng.gen::<u8>())
                .collect::<Vec<u8>>();
            let push_bytes_buf = PushBytesBuf::try_from(v.clone()).unwrap();
            values.push(Builder::new().push_slice(&push_bytes_buf).into_script());
            test_scripts.push(script! {
                { v }
            })
        }

        // OP_PUSHDATA2
        let large_data = (0..520).map(|_| rng.gen::<u8>()).collect::<Vec<u8>>();
        let push_bytes_buf = PushBytesBuf::try_from(large_data.clone()).unwrap();
        values.push(Builder::new().push_slice(&push_bytes_buf).into_script());
        test_scripts.push(script! {
            { large_data }
        });

        for (expected, script) in values.into_iter().zip(test_scripts.into_iter()) {
            println!("Testing script: {:?}", script);
            let extracted = extract_pushed_data_from_script(script.clone())
                .expect("Failed to extract pushed data");

            let mut witness = Witness::new();
            extracted.iter().for_each(|element| witness.push(element));

            let expected_script = script! {
                { expected }
            };

            let execution_info = execute_script(expected_script);

            let result_stack = (0..execution_info.final_stack.len()).map(|i| {
                execution_info
                    .final_stack
                    .get(i)
            }).collect::<Vec<_>>();

            assert_eq!(extracted, result_stack);

            assert!(
                execute_script(script! {
                    { witness }
                    { extracted }
                    OP_EQUAL
                })
                .success
            );
        }
    }

    #[test]
    fn test_parsing_scriptbuf() {
        let mut s = ScriptBuf::new();
        s.push_opcode(OP_PUSHBYTES_0);
        s.push_opcode(OP_ADD);
        s.push_slice([5; 73]);
        s.push_slice([37; 76]);
        s.push_opcode(OP_PUSHNUM_1);
        let debug_output = format!("{:?}", s);
        let converted = parse_scriptbuf_debug_to_bytes(String::from(" ") + &debug_output);
        assert_eq!(converted, s.to_bytes());
    }

    #[test]
    fn test_parsing_structuredscript() {
        let other_script_0 = script! {
            { 0 }
            { 1 }
            { 37 }
            OP_ADD
            OP_EQUALVERIFY
        };

        let other_script_1 = script! {
            OP_DIV
            OP_MUL
            OP_LSHIFT
        };

        let s = script! {
            { 123 }
            OP_ADD
            { other_script_0 }
            { vec![1] }
            { other_script_1 }
        };

        let mul_script =
            crate::bn254::fq::Fq::hinted_mul(0, ark_bn254::Fq::from(0), 1, ark_bn254::Fq::from(0));
        let testing_scripts = vec![
            s,
            crate::hash::blake3::blake3_compute_script(256),
            mul_script.0,
        ];
        for s in testing_scripts {
            let debug_output = format!("{:?}", s);
            assert_eq!(
                s.compile().to_bytes(),
                parse_structuredscript_debug_to_bytes(debug_output)
            );
        }
    }
}
