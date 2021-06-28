open Core;;
open Option;;

exception Err of string

let gen_semantics mnemonic operands opcode = "unimpl"

let gen_operand operand = 
  match operand with
  | "memarg" -> "memalign memoffset"
  | _ -> raise (Err ("can't handle operand " ^ operand))

let gen_followup operand = 
  match operand with
  | "memarg" -> "memalign; memoffset"
  | _ -> raise (Err ("can't handle operand " ^ operand))

let gen_constructor opcode operands = 
  [Printf.sprintf "opc=%s" opcode] @ (List.map operands gen_followup)
  |> String.concat ~sep:"; "

let gen_sleigh mnemonic operands opcode = 
  Printf.sprintf ":\"\"^indent^\"%s\" %s is %s; indent %s"
    mnemonic 
    (List.map operands gen_operand |> String.concat ~sep:" ")
    (gen_constructor opcode operands)
    (gen_semantics mnemonic operands opcode)

let fname = "wasm_opcodes.csv"
let lines = In_channel.read_lines fname

let () = List.iter lines (fun line -> 
  let csvs = String.split ~on:',' line in
  let opcode = match List.nth csvs 1 with Some x -> x in
  let op = String.split ~on:' ' (match List.nth csvs 0 with Some x -> x) in
  let sleigh = match op with
    mnemonics::operands -> gen_sleigh mnemonics operands opcode in
  Printf.printf "%s\n" sleigh
)
