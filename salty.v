import os
import math.big

struct LCG {
mut:
	state u64
}

fn (mut rng LCG) next() u32 {
	rng.state = rng.state * u64(6364136223846793005) + u64(1442695040888963407)
	return u32(rng.state >> 32)
}

fn (mut rng LCG) intn(n int) int {
	if n <= 0 {
		return 0
	}
	return int(rng.next() % u32(n))
}

struct Format {
	prefix      string
	payload_len int
}

fn pad_left_zero(val int, width int) string {
	mut s := val.str()
	for s.len < width {
		s = '0' + s
	}
	return s
}

fn parse_formats(raw string) ![]Format {
	if raw == '' {
		return error('Formats string cannot be empty')
	}
	mut formats := []Format{}
	parts := raw.split(',')
	for p in parts {
		sub := p.split(':')
		if sub.len != 2 {
			return error('Invalid format: "' + p + '". Must be "prefix:payload_len"')
		}
		prefix := sub[0]
		payload_len := sub[1].int()
		if payload_len <= 0 {
			return error('Payload length must be greater than 0')
		}
		formats << Format{
			prefix: prefix
			payload_len: payload_len
		}
	}
	return formats
}

fn get_shuffled_indices(len int, seed u64) []int {
	mut indices := []int{len: len}
	for i in 0..len {
		indices[i] = i
	}
	mut rng := LCG{state: seed}
	for i := len - 1; i > 0; i-- {
		j := rng.intn(i + 1)
		indices[i], indices[j] = indices[j], indices[i]
	}
	return indices
}

fn extract_numbers(text string) []string {
	mut numbers := []string{}
	mut current := ''
	for i := 0; i < text.len; i++ {
		ch := text[i]
		if ch >= `0` && ch <= `9` {
			current += ch.ascii_str()
		} else if ch == `+` {
			if current != '' {
				numbers << current
				current = ''
			}
			current = '+'
		} else {
			if current != '' {
				if current != '+' {
					numbers << current
				}
				current = ''
			}
		}
	}
	if current != '' && current != '+' {
		numbers << current
	}
	return numbers
}

fn hex_char_to_val(c u8) u8 {
	if c >= `0` && c <= `9` { return c - `0` }
	if c >= `a` && c <= `f` { return c - `a` + 10 }
	if c >= `A` && c <= `F` { return c - `A` + 10 }
	return 0
}

fn hex_to_bytes(hex_str string) ![]u8 {
	if hex_str.len % 2 != 0 {
		return error('Invalid hex string length')
	}
	mut bytes := []u8{cap: hex_str.len / 2}
	for i := 0; i < hex_str.len; i += 2 {
		high := hex_char_to_val(hex_str[i])
		low := hex_char_to_val(hex_str[i+1])
		bytes << u8((high << 4) | low)
	}
	return bytes
}

fn openssl_encrypt(plaintext string, password string) !string {
	tmp_plain := os.join_path(os.temp_dir(), 'plain_${os.getpid()}.txt')
	tmp_comp := os.join_path(os.temp_dir(), 'comp_${os.getpid()}.zst')
	tmp_enc := os.join_path(os.temp_dir(), 'enc_${os.getpid()}.bin')
	
	os.write_file(tmp_plain, plaintext)!
	
	zstd_cmd := 'zstd -19 -f ${tmp_plain} -o ${tmp_comp}'
	zstd_res := os.execute(zstd_cmd)
	os.rm(tmp_plain) or {}
	
	if zstd_res.exit_code != 0 {
		os.rm(tmp_comp) or {}
		return error('ZSTD compression failed: ' + zstd_res.output)
	}
	
	os.setenv('SALTY_PASS', password, true)
	
	cmd := 'openssl enc -chacha20 -nosalt -pass env:SALTY_PASS -pbkdf2 -in ${tmp_comp} -out ${tmp_enc}'
	res := os.execute(cmd)
	
	os.setenv('SALTY_PASS', '', true)
	os.rm(tmp_comp) or {}
	
	if res.exit_code != 0 {
		os.rm(tmp_enc) or {}
		return error('OpenSSL encryption failed: ' + res.output)
	}
	
	enc_bytes := os.read_bytes(tmp_enc)!
	os.rm(tmp_enc) or {}
	
	return enc_bytes.hex()
}

fn openssl_decrypt(hex_ciphertext string, password string) !string {
	enc_bytes := hex_to_bytes(hex_ciphertext)!
	
	tmp_enc := os.join_path(os.temp_dir(), 'enc_${os.getpid()}.bin')
	tmp_comp := os.join_path(os.temp_dir(), 'comp_${os.getpid()}.zst')
	tmp_plain := os.join_path(os.temp_dir(), 'plain_${os.getpid()}.txt')
	
	os.write_bytes(tmp_enc, enc_bytes)!
	os.setenv('SALTY_PASS', password, true)
	
	cmd := 'openssl enc -chacha20 -d -nosalt -pass env:SALTY_PASS -pbkdf2 -in ${tmp_enc} -out ${tmp_comp}'
	res := os.execute(cmd)
	
	os.setenv('SALTY_PASS', '', true)
	os.rm(tmp_enc) or {}
	
	if res.exit_code != 0 {
		os.rm(tmp_comp) or {}
		return error('OpenSSL decryption failed: ' + res.output)
	}
	
	zstd_cmd := 'zstd -d -f ${tmp_comp} -o ${tmp_plain}'
	zstd_res := os.execute(zstd_cmd)
	os.rm(tmp_comp) or {}
	
	if zstd_res.exit_code != 0 {
		os.rm(tmp_plain) or {}
		return error('ZSTD decompression failed: ' + zstd_res.output)
	}
	
	plaintext := os.read_file(tmp_plain)!
	os.rm(tmp_plain) or {}
	
	return plaintext
}

fn encrypt_flow(message string, password string, seed u64, formats []Format) ! {
	hex_ciphertext := openssl_encrypt(message, password)!

	big_int := big.integer_from_radix(hex_ciphertext, 16)!
	dec_payload := big_int.str()

	dec_str := pad_left_zero(dec_payload.len, 4) + dec_payload

	mut chunks := []string{}
	mut chunk_formats := []Format{}
	mut cursor := 0
	mut fmt_idx := 0
	for cursor < dec_str.len {
		fmt := formats[fmt_idx % formats.len]
		fmt_idx++

		mut size := fmt.payload_len
		mut is_last := false
		if cursor + size >= dec_str.len {
			size = dec_str.len - cursor
			is_last = true
		}

		mut chunk_data := dec_str[cursor..cursor + size]
		if is_last && chunk_data.len < fmt.payload_len {
			needed := fmt.payload_len - chunk_data.len
			mut rng := LCG{state: seed + 999}
			for _ in 0..needed {
				digit := rng.intn(10).str()
				chunk_data += digit
			}
		}

		chunks << chunk_data
		chunk_formats << fmt
		cursor += size
	}

	shuffled_indices := get_shuffled_indices(chunks.len, seed)
	mut trans_chunks := []string{len: chunks.len}
	for i in 0..chunks.len {
		trans_chunks[i] = chunks[shuffled_indices[i]]
	}

	mut proposed := []string{}
	for i in 0..chunks.len {
		orig_idx := shuffled_indices[i]
		fmt := chunk_formats[orig_idx]
		proposed << fmt.prefix + trans_chunks[i]
	}

	println('=== ENCRYPTION ===')
	println('Original payload length: ' + dec_payload.len.str() + ' digits')
	println('Chunk count: ' + chunks.len.str())
	println('\nProposed obfuscated numbers (Place these into your text in this EXACT order):')
	for idx, num in proposed {
		println('  ' + (idx + 1).str() + ': ' + num)
	}
}

fn decrypt_flow(carrier_text string, password string, seed u64, formats []Format) ! {
	found_numbers := extract_numbers(carrier_text)
	if found_numbers.len == 0 {
		return error('No numbers found in the carrier text.')
	}

	mut chunk_formats := []Format{}
	for i in 0..found_numbers.len {
		chunk_formats << formats[i % formats.len]
	}

	shuffled_indices := get_shuffled_indices(found_numbers.len, seed)

	mut original_chunks := []string{len: found_numbers.len}
	for i in 0..found_numbers.len {
		orig_idx := shuffled_indices[i]
		if orig_idx < 0 || orig_idx >= found_numbers.len {
			return error('Index mapping failed. Check your Seed, Formats sequence or Chunk count.')
		}
		fmt := chunk_formats[orig_idx]
		num := found_numbers[i]

		if !num.starts_with(fmt.prefix) {
			return error('Extracted number "' + num + '" does not match expected prefix "' + fmt.prefix + '". Check your text order or formats list.')
		}
		mut raw_payload := num[fmt.prefix.len..]
		
		if raw_payload.len > fmt.payload_len {
			raw_payload = raw_payload[0..fmt.payload_len]
		} else if raw_payload.len < fmt.payload_len {
			return error('Extracted number "' + num + '" has insufficient digits.')
		}

		original_chunks[orig_idx] = raw_payload
	}

	dec_str := original_chunks.join('')

	if dec_str.len < 4 {
		return error('Reconstructed string is too short.')
	}
	payload_len := dec_str[0..4].int()
	if 4 + payload_len > dec_str.len {
		return error('Calculated length exceeds decoded data.')
	}
	dec_payload := dec_str[4..4 + payload_len]

	big_int := big.integer_from_string(dec_payload)!
	mut hex_ciphertext := big_int.hex()
	if hex_ciphertext.len % 2 != 0 {
		hex_ciphertext = '0' + hex_ciphertext
	}

	plaintext := openssl_decrypt(hex_ciphertext, password)!

	println('=== DECRYPTION ===')
	println('Extracted chunks: ' + found_numbers.len.str())
	println('\nDecrypted Message:')
	println(plaintext)
}

fn print_help() {
	println('Usage: salty [encrypt|decrypt] [options]')
	println('Or simply run: salty (for interactive mode)')
	println('\nOptions:')
	println('  -m, --message "<msg>"     Plaintext message to encrypt (for encrypt mode)')
	println('  -t, --text "<text>"       Carrier text containing fake numbers (for decrypt mode)')
	println('  -p, --pass "<pass>"       OpenSSL encryption password')
	println('  -s, --seed <number>       Deterministic shuffling seed')
	println('  -f, --formats "<csv>"     Comma-separated list of formats (e.g. "+98912:7,603799:10")')
	println('  -h, --help                Show this help message')
}

fn run_interactive() ! {
	println('=== SALTY INTERACTIVE MODE ===')
	mode_choice := os.input('Choose Mode (1: Encrypt, 2: Decrypt): ').trim_space()
	if mode_choice != '1' && mode_choice != '2' {
		return error('Invalid mode choice.')
	}

	raw_formats := os.input('Enter Formats (e.g. "+98912:7,603799:10"): ').trim_space()
	formats := parse_formats(raw_formats)!

	seed_str := os.input('Enter Seed (number): ').trim_space()
	seed_val := seed_str.u64()

	password := os.input_password('Enter OpenSSL Password: ')!

	if mode_choice == '1' {
		message := os.input('Enter Message to encrypt: ')
		encrypt_flow(message, password, seed_val, formats)!
	} else {
		carrier_text := os.input('Enter Carrier Text to decrypt: ')
		decrypt_flow(carrier_text, password, seed_val, formats)!
	}
}

fn main() {
	args := os.args
	if args.len == 1 {
		run_interactive() or {
			println('Interactive mode failed: ${err}')
		}
		return
	}

	if '-h' in args || '--help' in args {
		print_help()
		return
	}

	mode := args[1]
	if mode != 'encrypt' && mode != 'decrypt' {
		println('Error: Mode must be "encrypt" or "decrypt"')
		print_help()
		return
	}

	mut message := ''
	mut carrier_text := ''
	mut password := ''
	mut seed_val := u64(0)
	mut raw_formats := ''

	for i := 2; i < args.len; i++ {
		arg := args[i]
		match arg {
			'-m', '--message' {
				if i + 1 < args.len { message = args[i + 1]; i++ }
			}
			'-t', '--text' {
				if i + 1 < args.len { carrier_text = args[i + 1]; i++ }
			}
			'-p', '--pass' {
				if i + 1 < args.len { password = args[i + 1]; i++ }
			}
			'-s', '--seed' {
				if i + 1 < args.len { seed_val = args[i + 1].u64(); i++ }
			}
			'-f', '--formats' {
				if i + 1 < args.len { raw_formats = args[i + 1]; i++ }
			}
			else {
				println('Warning: Unknown flag $arg')
			}
		}
	}

	if password == '' {
		println('Error: Password is required (-p or --pass)')
		return
	}

	if raw_formats == '' {
		println('Error: Formats are required (-f or --formats)')
		return
	}

	formats := parse_formats(raw_formats) or {
		println('Format parse error: ${err}')
		return
	}

	if mode == 'encrypt' {
		if message == '' {
			println('Error: Message required (-m)')
			return
		}
		encrypt_flow(message, password, seed_val, formats) or {
			println('Encryption failed: ${err}')
		}
	} else {
		if carrier_text == '' {
			println('Error: Carrier text required (-t)')
			return
		}
		decrypt_flow(carrier_text, password, seed_val, formats) or {
			println('Decryption failed: ${err}')
		}
	}
}
