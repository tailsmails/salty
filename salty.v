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
	if n <= 0 { return 0 }
	return int(rng.next() % u32(n))
}

struct Format {
	prefix      string
	payload_len int
}

struct InjSpot {
	orig_ch rune
	inj_ch  rune
}

fn pad_left_zero(val int, width int) string {
	mut s := val.str()
	for s.len < width { s = '0' + s }
	return s
}

fn parse_formats(raw string) ![]Format {
	if raw == '' { return error('Formats string cannot be empty') }
	mut formats := []Format{}
	for p in raw.split(',') {
		sub := p.split(':')
		if sub.len != 2 { return error('Invalid format: "' + p + '".') }
		payload_len := sub[1].int()
		if payload_len <= 0 { return error('Payload length must be > 0') }
		formats << Format{ prefix: sub[0], payload_len: payload_len }
	}
	return formats
}

fn get_shuffled_indices(len int, seed u64) []int {
	mut indices := []int{len: len}
	for i in 0 .. len { indices[i] = i }
	mut rng := LCG{state: seed}
	for i := len - 1; i > 0; i-- {
		j := rng.intn(i + 1)
		indices[i], indices[j] = indices[j], indices[i]
	}
	return indices
}

fn extract_numbers(text string) ![]string {
	mut numbers := []string{}
	mut current := ''
	for ch in text.runes() {
		is_digit := ch >= 48 && ch <= 57
		is_plus := ch == 43
		mut is_separator := ch == 32 || ch == 9 || ch == 10 || ch == 13 ||
							ch == 46 || ch == 44 || ch == 33 || ch == 63 ||
							ch == 58 || ch == 59 || ch == 45 || ch == 95 ||
							ch == 41 || ch == 40 || ch == 93 || ch == 91 ||
							ch == 47 || ch == 92
		if is_digit {
			current += ch.str()
		} else if is_plus {
			if current != '' {
				numbers << current
				current = ''
			}
			current = '+'
		} else if is_separator {
			if current != '' {
				if current != '+' { numbers << current }
				current = ''
			}
		} else {
			continue
		}
	}
	if current != '' && current != '+' { numbers << current }
	return numbers
}

fn hex_char_to_val(c u8) u8 {
	if c >= 48 && c <= 57 { return c - 48 }
	if c >= 97 && c <= 102 { return c - 87 }
	if c >= 65 && c <= 70 { return c - 55 }
	return 0
}

fn hex_to_bytes(hex_str string) ![]u8 {
	if hex_str.len % 2 != 0 { return error('Invalid hex string length') }
	mut bytes := []u8{cap: hex_str.len / 2}
	for i := 0; i < hex_str.len; i += 2 {
		high := hex_char_to_val(hex_str[i])
		low := hex_char_to_val(hex_str[i + 1])
		bytes << u8((high << 4) | low)
	}
	return bytes
}

fn openssl_encrypt(plaintext string, password string) !string {
	tmp_plain := os.join_path(os.temp_dir(), 'plain_${os.getpid()}.txt')
	tmp_comp := os.join_path(os.temp_dir(), 'comp_${os.getpid()}.zst')
	tmp_enc := os.join_path(os.temp_dir(), 'enc_${os.getpid()}.bin')

	os.write_file(tmp_plain, plaintext)!
	zstd_res := os.execute('zstd -19 -f ${tmp_plain} -o ${tmp_comp}')
	os.rm(tmp_plain) or {}
	if zstd_res.exit_code != 0 { os.rm(tmp_comp) or {}; return error('ZSTD compression failed') }

	os.setenv('SALTY_PASS', password, true)
	res := os.execute('openssl enc -chacha20 -nosalt -pass env:SALTY_PASS -pbkdf2 -in ${tmp_comp} -out ${tmp_enc}')
	os.setenv('SALTY_PASS', '', true)
	os.rm(tmp_comp) or {}

	if res.exit_code != 0 { os.rm(tmp_enc) or {}; return error('OpenSSL failed') }
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
	res := os.execute('openssl enc -chacha20 -d -nosalt -pass env:SALTY_PASS -pbkdf2 -in ${tmp_enc} -out ${tmp_comp}')
	os.setenv('SALTY_PASS', '', true)
	os.rm(tmp_enc) or {}

	if res.exit_code != 0 { os.rm(tmp_comp) or {}; return error('OpenSSL failed') }
	zstd_res := os.execute('zstd -d -f ${tmp_comp} -o ${tmp_plain}')
	os.rm(tmp_comp) or {}

	if zstd_res.exit_code != 0 { os.rm(tmp_plain) or {}; return error('ZSTD failed') }
	plaintext := os.read_file(tmp_plain)!
	os.rm(tmp_plain) or {}
	return plaintext
}

fn get_english_qwerty_neighbors(c rune) []rune {
	mut neighbors := []rune{}
	rows := ["`1234567890-=", "qwertyuiop[]\\", "asdfghjkl;'", "zxcvbnm,./"]
	ch := if c >= 65 && c <= 90 { c + 32 } else { c }
	
	mut r_idx := -1
	mut c_idx := -1
	for i in 0 .. rows.len {
		runes := rows[i].runes()
		for j in 0 .. runes.len {
			if runes[j] == ch {
				r_idx = i; c_idx = j; break
			}
		}
		if r_idx != -1 { break }
	}
	
	if r_idx != -1 {
		for i := r_idx - 1; i <= r_idx + 1; i++ {
			for j := c_idx - 1; j <= c_idx + 1; j++ {
				if i == r_idx && j == c_idx { continue }
				if i >= 0 && i < rows.len {
					row_runes := rows[i].runes()
					if j >= 0 && j < row_runes.len { neighbors << row_runes[j] }
				}
			}
		}
	}
	return neighbors
}

fn get_custom_map_neighbors(ch rune, key_map []rune) []rune {
	mut neighbors := []rune{}
	idx := key_map.index(ch)
	if idx != -1 {
		for offset in [-3, -2, -1, 1, 2, 3] {
			target := idx + offset
			if target >= 0 && target < key_map.len { neighbors << key_map[target] }
		}
	}
	return neighbors
}

fn get_stego_choices(ch rune, custom_chars []rune, key_map []rune, use_qwerty bool, fallback_chars []rune) []rune {
	mut raw := []rune{}
	if custom_chars.len > 0 { raw = custom_chars.clone() }
	else if key_map.len > 0 { 
		raw = get_custom_map_neighbors(ch, key_map)
		if raw.len == 0 { raw = key_map.clone() }
	}
	else if use_qwerty { raw = get_english_qwerty_neighbors(ch) }
	
	if raw.len < 2 {
		for r in fallback_chars { if r != ch { raw << r } }
	}
	
	mut unique := []rune{}
	for r in raw { if !(r in unique) { unique << r } }
	unique.sort()
	return unique
}

fn encrypt_text_stego(message string, cover_text string, password string, seed u64, intensity int, typo_chars_str string, key_map_str string, use_qwerty bool) ! {
	hex_cipher := openssl_encrypt(message, password)!
	safe_hex := '1' + hex_cipher
	mut p := big.integer_from_radix(safe_hex, 16)!
	zero := big.integer_from_int(0)
	
	mut fallback_chars := []rune{}
	for r in cover_text.runes() {
		if !(r in fallback_chars) && r != 32 && r != 10 && r != 13 { fallback_chars << r }
	}
	fallback_chars.sort()

	mut custom_chars := []rune{}
	if typo_chars_str != '' {
		for r in typo_chars_str.replace(',', '').trim_space().runes() { custom_chars << r }
	}
	mut key_map_runes := []rune{}
	if key_map_str != '' {
		for r in key_map_str.replace(',', '').trim_space().runes() { key_map_runes << r }
	}

	mut rng := LCG{state: seed}
	mut modified_text := []rune{}
	
	for ch in cover_text.runes() {
		modified_text << ch
		if rng.intn(100) < intensity {
			choices := get_stego_choices(ch, custom_chars, key_map_runes, use_qwerty, fallback_chars)
			if choices.len > 1 {
				if p > zero {
					radix := choices.len
					radix_big := big.integer_from_int(radix)
					rem_big := p % radix_big
					rem := rem_big.str().int()
					p = p / radix_big
					modified_text << choices[rem]
				} else {
					modified_text << choices[0]
				}
			}
		}
	}
	
	if p > zero {
		return error("Cover text is too short or intensity is too low to hide the encrypted payload. Increase text length or intensity.")
	}
	
	println('=== STEGANOGRAPHY ENCRYPTION ===')
	println('Carrier (Copy this completely):')
	println(modified_text.string())
}

fn decrypt_text_stego(modified_text string, password string, seed u64, intensity int, typo_chars_str string, key_map_str string, use_qwerty bool) ! {
	mut rng := LCG{state: seed}
	mut original_runes := []rune{}
	
	mut spots := []InjSpot{}
	
	modified_runes := modified_text.runes()
	mut i := 0
	for i < modified_runes.len {
		ch := modified_runes[i]
		original_runes << ch
		i++
		
		if rng.intn(100) < intensity {
			if i < modified_runes.len {
				spots << InjSpot{orig_ch: ch, inj_ch: modified_runes[i]}
				i++
			}
		}
	}
	
	mut fallback_chars := []rune{}
	for r in original_runes {
		if !(r in fallback_chars) && r != 32 && r != 10 && r != 13 { fallback_chars << r }
	}
	fallback_chars.sort()

	mut custom_chars := []rune{}
	if typo_chars_str != '' {
		for r in typo_chars_str.replace(',', '').trim_space().runes() { custom_chars << r }
	}
	mut key_map_runes := []rune{}
	if key_map_str != '' {
		for r in key_map_str.replace(',', '').trim_space().runes() { key_map_runes << r }
	}

	mut p := big.integer_from_int(0)
	mut mult := big.integer_from_int(1)
	
	for spot in spots {
		choices := get_stego_choices(spot.orig_ch, custom_chars, key_map_runes, use_qwerty, fallback_chars)
		if choices.len > 1 {
			radix := choices.len
			rem := choices.index(spot.inj_ch)
			if rem == -1 { return error("Data corruption: Extracted typo char not in valid choices.") }
			
			rem_big := big.integer_from_int(rem)
			p = p + (rem_big * mult)
			mult = mult * big.integer_from_int(radix)
		}
	}
	
	hex_payload := p.hex()
	if hex_payload.len == 0 || hex_payload[0] != `1` {
		return error("Decryption failed: Corruption or wrong parameters (Seed/Intensity/Password).")
	}
	
	hex_cipher := hex_payload[1..]
	plaintext := openssl_decrypt(hex_cipher, password)!
	
	println('=== DECRYPTION ===')
	println('Hidden Payload Extracted successfully.')
	println('\nDecrypted Message:')
	println(plaintext)
}

fn encrypt_number_flow(message string, password string, seed u64, formats []Format) ! {
	hex_ciphertext := openssl_encrypt(message, password)!
	big_int := big.integer_from_radix(hex_ciphertext, 16)!
	dec_payload := big_int.str()
	dec_str := pad_left_zero(dec_payload.len, 4) + dec_payload

	mut chunks := []string{}
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

		mut chunk_data := dec_str[cursor .. cursor + size]
		if is_last && chunk_data.len < fmt.payload_len {
			needed := fmt.payload_len - chunk_data.len
			mut rng := LCG{state: seed + 999}
			for _ in 0 .. needed { chunk_data += rng.intn(10).str() }
		}

		chunks << fmt.prefix + chunk_data
		cursor += size
	}

	shuffled_indices := get_shuffled_indices(chunks.len, seed)
	mut proposed := []string{len: chunks.len}
	for i in 0 .. chunks.len { proposed[i] = chunks[shuffled_indices[i]] }

	println('=== NUMBER ENCRYPTION ===')
	println('Proposed obfuscated numbers (Place these into your text in this EXACT order):')
	for idx, num in proposed { println('  ' + (idx + 1).str() + ': ' + num) }
}

fn decrypt_number_flow(carrier_text string, password string, seed u64, formats []Format) ! {
	found_numbers := extract_numbers(carrier_text)!
	if found_numbers.len == 0 { return error('No numbers found in the carrier text.') }

	mut chunk_formats := []Format{}
	for i in 0 .. found_numbers.len { chunk_formats << formats[i % formats.len] }

	shuffled_indices := get_shuffled_indices(found_numbers.len, seed)
	mut original_chunks := []string{len: found_numbers.len}
	
	for i in 0 .. found_numbers.len {
		orig_idx := shuffled_indices[i]
		fmt := chunk_formats[orig_idx]
		num := found_numbers[i]

		if !num.starts_with(fmt.prefix) { return error('Prefix mismatch on: ' + num) }
		mut raw_payload := num[fmt.prefix.len..]
		if raw_payload.len > fmt.payload_len { raw_payload = raw_payload[0 .. fmt.payload_len] }
		original_chunks[orig_idx] = raw_payload
	}

	dec_str := original_chunks.join('')
	payload_len := dec_str[0 .. 4].int()
	dec_payload := dec_str[4 .. 4 + payload_len]

	big_int := big.integer_from_string(dec_payload)!
	mut hex_ciphertext := big_int.hex()
	if hex_ciphertext.len % 2 != 0 { hex_ciphertext = '0' + hex_ciphertext }

	plaintext := openssl_decrypt(hex_ciphertext, password)!
	println('=== DECRYPTION ===\n' + plaintext)
}

fn print_help() {
	println('Usage: salty [encrypt|decrypt] [options]')
	println('Or simply run: salty (for interactive mode)')
	println('\nGeneral Options:')
	println('  -m, --message "<str>"      Plaintext message to encrypt')
	println('  -t, --text "<str>"         Cover text (for Text mode) OR Carrier text (for Decryption)')
	println('  -p, --pass "<str>"         OpenSSL encryption password')
	println('  -s, --seed <u64>           Deterministic seed')
	println('\nMethod 1: Number Steganography Options:')
	println('  -f, --formats "<str>"      Comma-separated list of formats (e.g. "+98912:7,6037:10")')
	println('\nMethod 2: Text Steganography (Typo) Options:')
	println('  -ti, --typo-intensity <int> Intensity of typos (e.g. 30)')
	println('  -tc, --typo-chars "<str>"  Custom typo letters (e.g. "a,z,c")')
	println('  -km, --key-map "<str>"     Custom keyboard map (e.g. "ضصث...")')
	println('  -q, --qwerty               Enable English QWERTY mode')
	println('  -h, --help                 Show this help message')
}

fn run_interactive() ! {
	println('=== SALTY INTERACTIVE MODE ===')
	method := os.input('Choose Carrier Method (1: Fake Numbers, 2: Text Typos [Steganography]): ').trim_space()
	mode := os.input('Choose Action (1: Encrypt, 2: Decrypt): ').trim_space()
	password := os.input_password('Enter OpenSSL Password: ')!
	
	if method == '1' {
		formats := parse_formats(os.input('Enter Formats (e.g. "+98912:7,603799:10"): ').trim_space())!
		seed_val := os.input('Enter Seed (number): ').trim_space().u64()
		if mode == '1' {
			msg := os.input('Enter Message to encrypt: ')
			encrypt_number_flow(msg, password, seed_val, formats)!
		} else {
			txt := os.input('Enter Carrier Text to decrypt: ')
			decrypt_number_flow(txt, password, seed_val, formats)!
		}
	} else if method == '2' {
		seed_val := os.input('Enter Typo Seed (number): ').trim_space().u64()
		intensity := os.input('Enter Typo Intensity (10-90, e.g. 30): ').trim_space().int()
		qwerty_ans := os.input('Use English QWERTY? (y/n): ').trim_space().to_lower()
		use_qwerty := qwerty_ans == 'y'
		
		mut key_map := ''
		mut typo_chars := ''
		if !use_qwerty {
			key_map = os.input('Enter Custom Keyboard Map (e.g. "ضصث..." or empty to skip): ').trim_space()
			if key_map == '' { typo_chars = os.input('Enter Custom Typo Chars (e.g. "a,b,c" or empty for Auto-Text mode): ').trim_space() }
		}

		if mode == '1' {
			msg := os.input('Enter Message to encrypt: ')
			cover := os.input('Enter Reference Text (The text to hide payload inside): ')
			encrypt_text_stego(msg, cover, password, seed_val, intensity, typo_chars, key_map, use_qwerty)!
		} else {
			carrier := os.input('Enter the text containing the hidden typos: ')
			decrypt_text_stego(carrier, password, seed_val, intensity, typo_chars, key_map, use_qwerty)!
		}
	}
}

fn main() {
	args := os.args
	if args.len == 1 {
		run_interactive() or { println('Error: ${err}') }
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
	mut text_input := ''
	mut password := ''
	mut seed_val := u64(0)
	mut raw_formats := ''
	mut typo_intensity := 0
	mut typo_chars := ''
	mut key_map := ''
	mut use_qwerty := false

	for i := 2; i < args.len; i++ {
		arg := args[i]
		match arg {
			'-m', '--message' { if i + 1 < args.len { message = args[i + 1]; i++ } }
			'-t', '--text' { if i + 1 < args.len { text_input = args[i + 1]; i++ } }
			'-p', '--pass' { if i + 1 < args.len { password = args[i + 1]; i++ } }
			'-s', '--seed' { if i + 1 < args.len { seed_val = args[i + 1].u64(); i++ } }
			'-f', '--formats' { if i + 1 < args.len { raw_formats = args[i + 1]; i++ } }
			'-ti', '--typo-intensity' { if i + 1 < args.len { typo_intensity = args[i + 1].int(); i++ } }
			'-tc', '--typo-chars' { if i + 1 < args.len { typo_chars = args[i + 1]; i++ } }
			'-km', '--key-map' { if i + 1 < args.len { key_map = args[i + 1]; i++ } }
			'-q', '--qwerty' { use_qwerty = true }
			else { println('Warning: Unknown flag $arg') }
		}
	}

	if password == '' {
		println('Error: Password is required (-p or --pass)')
		return
	}

	if raw_formats != '' {
		formats := parse_formats(raw_formats) or {
			println('Format parse error: ${err}')
			return
		}
		if mode == 'encrypt' {
			if message == '' { println('Error: Message required (-m)'); return }
			encrypt_number_flow(message, password, seed_val, formats) or { println('Encryption failed: ${err}') }
		} else {
			if text_input == '' { println('Error: Carrier text required (-t)'); return }
			decrypt_number_flow(text_input, password, seed_val, formats) or { println('Decryption failed: ${err}') }
		}
	} else if typo_intensity > 0 {
		if mode == 'encrypt' {
			if message == '' { println('Error: Message required (-m)'); return }
			if text_input == '' { println('Error: Cover text required (-t)'); return }
			encrypt_text_stego(message, text_input, password, seed_val, typo_intensity, typo_chars, key_map, use_qwerty) or { println('Encryption failed: ${err}') }
		} else {
			if text_input == '' { println('Error: Carrier text required (-t)'); return }
			decrypt_text_stego(text_input, password, seed_val, typo_intensity, typo_chars, key_map, use_qwerty) or { println('Decryption failed: ${err}') }
		}
	} else {
		println('Error: You must provide either --formats (for Number Mode) or --typo-intensity (for Text Mode).')
		print_help()
	}
}
