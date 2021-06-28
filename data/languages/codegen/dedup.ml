open Core;;

let fname = "wasm_opcodes.csv" in 
let lines = In_channel.read_lines fname in
let processed = List.map lines (fun line -> List.map (String.split_on_chars ~on:[','] line) (fun item -> String.sub item 0 ((String.length item) / 2))) in
List.map processed (fun line -> String.concat ~sep:", " line) |> String.concat ~sep:"\n" |> print_string;;