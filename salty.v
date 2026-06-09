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

struct DecryptSpot {
	rem   int
	radix int
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

	defer {
		os.rm(tmp_plain) or {}
		os.rm(tmp_comp) or {}
		os.rm(tmp_enc) or {}
	}

	os.write_file(tmp_plain, plaintext)!
	zstd_res := os.execute('zstd -19 -q -f ${tmp_plain} -o ${tmp_comp}')
	if zstd_res.exit_code != 0 { return error('ZSTD compression failed') }

	os.setenv('SALTY_PASS', password, true)
	res := os.execute('openssl enc -chacha20 -pass env:SALTY_PASS -pbkdf2 -iter 10000 -in ${tmp_comp} -out ${tmp_enc}')
	os.setenv('SALTY_PASS', '', true)

	if res.exit_code != 0 { return error('OpenSSL failed') }
	enc_bytes := os.read_bytes(tmp_enc)!
	return enc_bytes.hex()
}

fn openssl_decrypt(hex_ciphertext string, password string) !string {
	tmp_enc := os.join_path(os.temp_dir(), 'enc_${os.getpid()}.bin')
	tmp_comp := os.join_path(os.temp_dir(), 'comp_${os.getpid()}.zst')
	tmp_plain := os.join_path(os.temp_dir(), 'plain_${os.getpid()}.txt')

	defer {
		os.rm(tmp_enc) or {}
		os.rm(tmp_comp) or {}
		os.rm(tmp_plain) or {}
	}

	enc_bytes := hex_to_bytes(hex_ciphertext)!
	os.write_bytes(tmp_enc, enc_bytes)!

	os.setenv('SALTY_PASS', password, true)
	res := os.execute('openssl enc -chacha20 -d -pass env:SALTY_PASS -pbkdf2 -iter 10000 -in ${tmp_enc} -out ${tmp_comp}')
	os.setenv('SALTY_PASS', '', true)

	if res.exit_code != 0 { return error('OpenSSL decryption failed (Wrong password?)') }

	zstd_res := os.execute('zstd -d -q -f ${tmp_comp} -o ${tmp_plain}')
	if zstd_res.exit_code != 0 { return error('ZSTD decompression failed') }

	plaintext := os.read_file(tmp_plain)!
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

fn encrypt_text_stego(message string, cover_text string, password string, seed u64, intensity int, typo_chars_str string, key_map_str string, use_qwerty bool, overwrite bool, transpose bool) ! {
	mut real_overwrite := overwrite
	if transpose {
		real_overwrite = true
	}

	hex_cipher := openssl_encrypt(message, password)!
	mut p := big.integer_from_radix('1' + hex_cipher, 16)!
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
	runes := cover_text.runes()
	mut modified_text := []rune{}
	
	mut i := 0
	for i < runes.len {
		ch := runes[i]
		if rng.intn(100) < intensity {
			mut use_swap := false
			if transpose {
				has_keyboard := use_qwerty || key_map_runes.len > 0 || custom_chars.len > 0
				if !has_keyboard {
					use_swap = true
				} else {
					use_swap = rng.intn(2) == 0
				}
			}

			if use_swap && i < runes.len - 1 && runes[i] != runes[i+1] {
				mut rem := 0
				if p > zero {
					radix_big := big.integer_from_int(2)
					rem = (p % radix_big).str().int()
					p = p / radix_big
				} else {
					rem = 0 
				}

				if rem == 1 {
					modified_text << runes[i+1]
					modified_text << runes[i]
				} else {
					modified_text << runes[i]
					modified_text << runes[i+1]
				}
				i += 2
				continue
			} else {
				choices := get_stego_choices(ch, custom_chars, key_map_runes, use_qwerty, fallback_chars)
				if choices.len > 1 {
					mut rem := 0
					if p > zero {
						radix := choices.len
						radix_big := big.integer_from_int(radix)
						rem = (p % radix_big).str().int()
						p = p / radix_big
					} else {
						rem = 0 
					}
					selected_char := choices[rem]
					
					if real_overwrite {
						modified_text << selected_char
					} else {
						modified_text << ch
						modified_text << selected_char
					}
					i++
					continue
				}
			}
		}
		modified_text << ch
		i++
	}
	
	if p > zero {
		return error("Cover text is too short or intensity is too low.")
	}
	
	println('=== STEGANOGRAPHY ENCRYPTION ===')
	if transpose { println('Mode: TRANSPOSITION (Active)') }
	if real_overwrite { println('Mode: OVERWRITE (Length preserved)') } else { println('Mode: INSERTION') }
	println('Carrier (Copy this completely):')
	println(modified_text.string())
}

fn decrypt_text_stego(modified_text string, ref_text string, password string, seed u64, intensity int, typo_chars_str string, key_map_str string, use_qwerty bool, overwrite bool, transpose bool) ! {
	mut rng := LCG{state: seed}
	modified_runes := modified_text.runes()
	
	mut spots := []DecryptSpot{}

	mut custom_chars := []rune{}
	if typo_chars_str != '' {
		for r in typo_chars_str.replace(',', '').trim_space().runes() { custom_chars << r }
	}
	mut key_map_runes := []rune{}
	if key_map_str != '' {
		for r in key_map_str.replace(',', '').trim_space().runes() { key_map_runes << r }
	}

	mut real_overwrite := overwrite
	if transpose {
		real_overwrite = true
	}

	if real_overwrite {
		if ref_text == '' {
			return error("Reference text (-r) is REQUIRED for decryption in Overwrite/Transpose mode!")
		}
		ref_runes := ref_text.runes()

		mut fallback_chars := []rune{}
		for r in ref_runes {
			if !(r in fallback_chars) && r != 32 && r != 10 && r != 13 { fallback_chars << r }
		}
		fallback_chars.sort()

		mut i := 0
		mut ref_idx := 0
		for ref_idx < ref_runes.len {
			if i >= modified_runes.len { break }

			if rng.intn(100) < intensity {
				mut use_swap := false
				if transpose {
					has_keyboard := use_qwerty || key_map_runes.len > 0 || custom_chars.len > 0
					if !has_keyboard {
						use_swap = true
					} else {
						use_swap = rng.intn(2) == 0
					}
				}

				if use_swap && ref_idx < ref_runes.len - 1 && ref_runes[ref_idx] != ref_runes[ref_idx+1] {
					if i < modified_runes.len - 1 {
						mut rem := 0
						if modified_runes[i] == ref_runes[ref_idx+1] && modified_runes[i+1] == ref_runes[ref_idx] {
							rem = 1
						} else if modified_runes[i] == ref_runes[ref_idx] && modified_runes[i+1] == ref_runes[ref_idx+1] {
							rem = 0
						} else {
							return error("Data corruption detected at transposition spot!")
						}
						spots << DecryptSpot{rem: rem, radix: 2}
						i += 2
						ref_idx += 2
						continue
					}
				} else {
					choices := get_stego_choices(ref_runes[ref_idx], custom_chars, key_map_runes, use_qwerty, fallback_chars)
					if choices.len > 1 {
						carrier_char := modified_runes[i]
						rem := choices.index(carrier_char)
						if rem == -1 {
							return error("Data corruption: Extracted typo char not in valid choices.")
						}
						spots << DecryptSpot{rem: rem, radix: choices.len}
						i++
						ref_idx++
						continue
					}
				}
			}
			i++
			ref_idx++
		}
	} else {
		mut original_runes := []rune{}
		mut i := 0
		for i < modified_runes.len {
			ch := modified_runes[i]
			original_runes << ch
			i++
			if rng.intn(100) < intensity {
				if i < modified_runes.len {
					spots << DecryptSpot{rem: -1, radix: -1}
					i++
				}
			}
		}

		mut fallback_chars_ins := []rune{}
		for r in original_runes {
			if !(r in fallback_chars_ins) && r != 32 && r != 10 && r != 13 { fallback_chars_ins << r }
		}
		fallback_chars_ins.sort()

		mut rng_ins := LCG{state: seed}
		mut original_idx := 0
		mut carrier_idx := 0
		mut spot_idx := 0

		for original_idx < original_runes.len {
			ch := original_runes[original_idx]
			carrier_idx++

			if rng_ins.intn(100) < intensity {
				if carrier_idx < modified_runes.len {
					inserted_char := modified_runes[carrier_idx]
					carrier_idx++

					choices := get_stego_choices(ch, custom_chars, key_map_runes, use_qwerty, fallback_chars_ins)
					if choices.len > 1 {
						rem := choices.index(inserted_char)
						if rem != -1 {
							spots[spot_idx] = DecryptSpot{rem: rem, radix: choices.len}
							spot_idx++
						}
					}
				}
			}
			original_idx++
		}
	}

	mut p := big.integer_from_int(0)
	mut mult := big.integer_from_int(1)
	
	for spot in spots {
		if spot.radix > 1 {
			rem_big := big.integer_from_int(spot.rem)
			p = p + (rem_big * mult)
			mult = mult * big.integer_from_int(spot.radix)
		}
	}
	
	hex_payload := p.hex()
	if hex_payload.len == 0 || hex_payload[0] != `1` {
		return error("Decryption failed: Corruption or wrong parameters (Seed/Intensity/Password).")
	}
	
	hex_cipher := hex_payload[1..]
	plaintext := openssl_decrypt(hex_cipher, password)!
	
	println('=== DECRYPTION ===\n${plaintext}')
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
	println('Proposed obfuscated numbers:')
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

fn parse_mapping(raw string) map[string][]string {
	mut m := map[string][]string{}
	if raw == '' { return m }
	pairs := raw.split(',')
	for pair in pairs {
		parts := pair.split(':')
		if parts.len >= 2 {
			key := parts[0].trim_space()
			mut values := []string{}
			for v in parts[1..] {
				trimmed := v.trim_space()
				if trimmed != '' {
					values << trimmed
				}
			}
			m[key] = values
		}
	}
	return m
}

fn reverse_mapping(m map[string][]string) map[string]string {
	mut rev := map[string]string{}
	for k, vals in m {
		for v in vals {
			rev[v] = k
		}
	}
	return rev
}

fn sort_strings_by_length_desc(mut arr []string) {
	for i := 0; i < arr.len; i++ {
		for j := i + 1; j < arr.len; j++ {
			if arr[i].len < arr[j].len {
				arr[i], arr[j] = arr[j], arr[i]
			}
		}
	}
}

fn get_noise_chars(custom_str string) []rune {
	if custom_str != '' {
		mut runes := []rune{}
		for r in custom_str.replace(',', '').trim_space().runes() {
			runes << r
		}
		if runes.len > 0 {
			return runes
		}
	}
	return [
		`*`, `~`, `_`, `•`, `°`, `†`, `‡`, `▲`, `▼`, `◆`, `◇`, `■`, `□`, 
		`◀`, `▶`, `♠`, `♥`, `♦`, `♣`, `★`, `☆`, `✦`, `✧`, `✪`, `✿`, `❀`
	]
}

fn apply_obfuscation(text string, m map[string][]string, noise_intensity int, noise_chars []rune, seed u64) string {
	mut rng := LCG{state: seed}
	runes := text.runes()
	mut result := []rune{}

	for i := 0; i < runes.len; i++ {
		r := runes[i]
		r_str := r.str()
		
		if r_str in m {
			options := m[r_str]
			if options.len > 0 {
				idx := rng.intn(options.len)
				opt_runes := options[idx].runes()
				for opt_r in opt_runes {
					result << opt_r
				}
			} else {
				result << r
			}
		} else {
			result << r
		}
		
		if noise_intensity > 0 && noise_chars.len > 0 {
			if rng.intn(100) < noise_intensity {
				noise_idx := rng.intn(noise_chars.len)
				result << noise_chars[noise_idx]
			}
		}
	}
	return result.string()
}

fn apply_deobfuscation(text string, m map[string][]string, noise_chars []rune) string {
	mut cleaned_runes := []rune{}
	for r in text.runes() {
		if !(r in noise_chars) {
			cleaned_runes << r
		}
	}
	cleaned_text := cleaned_runes.string()
	
	rev := reverse_mapping(m)
	mut keys := rev.keys()
	sort_strings_by_length_desc(mut keys)

	mut out := cleaned_text
	for k in keys {
		v := rev[k]
		out = out.replace(k, v)
	}
	return out
}

fn print_help() {
	println('Usage: salty [encrypt|decrypt|obfuscate] [options]')
	println('Or simply run: salty (for interactive mode)')
	println('\nGeneral Options:')
	println('  -m, --message "<str>"      Plaintext message to encrypt')
	println('  -t, --text "<str>"         Cover text (for Encrypt) OR Carrier text (for Decrypt)')
	println('  -p, --pass "<str>"         OpenSSL encryption password')
	println('  -s, --seed <u64>           Deterministic seed')
	println('\nMethod 1: Number Steganography Options:')
	println('  -f, --formats "<str>"      Comma-separated list of formats (e.g. "+98912:7,6037:10")')
	println('\nMethod 2: Text Steganography (Typo) Options:')
	println('  -ti, --typo-intensity <int> Intensity of typos (e.g. 30)')
	println('  -tc, --typo-chars "<str>"  Custom typo letters (e.g. "a,z,c")')
	println('  -km, --key-map "<str>"     Custom keyboard map (e.g. "ضصث...")')
	println('  -q, --qwerty               Enable English QWERTY mode')
	println('  -o, --overwrite            OVERWRITE characters instead of inserting them')
	println('  -tr, --transpose           Transpose (swap) adjacent characters')
	println('  -r, --ref "<str>"          Original Reference Text (REQUIRED for Overwrite/Transpose Decrypt)')
	println('\nMethod 3: Custom Visual Obfuscation (Homoglyphs & Noise Injection):')
	println('  -map, --mapping "<str>"    Manual map for replacements (Format: "from:to1:to2,from:to")')
	println('  -ni, --noise-intensity <int> Intensity of noise injection (0-100)')
	println('  -nc, --noise-chars "<str>" Custom noise symbols (or empty for auto-pool)')
	println('  -d, --deobfuscate          Reverse the manual map (Deobfuscate)')
	println('  -h, --help                 Show this help message')
}

fn run_interactive() ! {
	println('=== SALTY INTERACTIVE MODE ===')
	method := os.input('Choose Carrier Method (1: Fake Numbers, 2: Text Typos, 3: Custom Manual Obfuscation): ').trim_space()
	
	if method == '1' || method == '2' {
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
		} else {
			seed_val := os.input('Enter Typo Seed (number): ').trim_space().u64()
			intensity := os.input('Enter Typo Intensity (10-90, e.g. 30): ').trim_space().int()
			qwerty_ans := os.input('Use English QWERTY? (y/n): ').trim_space().to_lower()
			use_qwerty := qwerty_ans == 'y'
			
			overwrite_ans := os.input('Overwrite characters instead of inserting? (y/n): ').trim_space().to_lower()
			overwrite := overwrite_ans == 'y'

			transpose_ans := os.input('Enable Transposition (swapping adjacent letters)? (y/n): ').trim_space().to_lower()
			transpose := transpose_ans == 'y'
			
			mut key_map := ''
			mut typo_chars := ''
			if !use_qwerty {
				key_map = os.input('Enter Custom Keyboard Map (e.g. "ضصث..." or empty to skip): ').trim_space()
				if key_map == '' { typo_chars = os.input('Enter Custom Typo Chars (e.g. "a,b,c" or empty): ').trim_space() }
			}

			if mode == '1' {
				msg := os.input('Enter Message to encrypt: ')
				cover := os.input('Enter Reference Text (The text to hide payload inside): ')
				encrypt_text_stego(msg, cover, password, seed_val, intensity, typo_chars, key_map, use_qwerty, overwrite, transpose)!
			} else {
				carrier := os.input('Enter the Carrier text: ')
				mut ref_text := ''
				if overwrite || transpose {
					ref_text = os.input('Enter ORIGINAL Reference Text: ')
				}
				decrypt_text_stego(carrier, ref_text, password, seed_val, intensity, typo_chars, key_map, use_qwerty, overwrite, transpose)!
			}
		}
	} else if method == '3' {
		mode_obf := os.input('Choose Action (1: Obfuscate, 2: Deobfuscate): ').trim_space()
		text_input := os.input('Enter your text: ')
		mapping_str := os.input('Enter mapping (Format: "from:to1:to2,from:to"): ').trim_space()
		
		noise_int_str := os.input('Enter Noise Intensity (0-100, or 0 to skip): ').trim_space()
		noise_int := noise_int_str.int()
		
		mut nc_str := ''
		if noise_int > 0 {
			nc_str = os.input('Enter Custom Noise Characters (leave empty for default pool): ').trim_space()
		}
		
		seed_str := os.input('Enter Seed (for random choices, e.g. 1): ').trim_space()
		seed_val := seed_str.u64()

		m := parse_mapping(mapping_str)
		noise_chars := get_noise_chars(nc_str)

		if mode_obf == '2' {
			result := apply_deobfuscation(text_input, m, noise_chars)
			println('\n=== DE-OBFUSCATED TEXT ===\n' + result)
		} else {
			result := apply_obfuscation(text_input, m, noise_int, noise_chars, seed_val)
			println('\n=== OBFUSCATED TEXT ===\n' + result)
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
	if mode != 'encrypt' && mode != 'decrypt' && mode != 'obfuscate' {
		println('Error: Mode must be "encrypt", "decrypt" or "obfuscate"')
		print_help()
		return
	}

	mut message := ''
	mut text_input := ''
	mut ref_text := ''
	mut password := ''
	mut seed_val := u64(0)
	mut raw_formats := ''
	mut typo_intensity := 0
	mut typo_chars := ''
	mut key_map := ''
	mut use_qwerty := false
	mut overwrite := false
	mut transpose := false
	mut mapping_str := ''
	mut deobfuscate := false
	mut noise_intensity := 0
	mut noise_chars_str := ''

	for i := 2; i < args.len; i++ {
		arg := args[i]
		match arg {
			'-m', '--message' { if i + 1 < args.len { message = args[i + 1]; i++ } }
			'-t', '--text' { if i + 1 < args.len { text_input = args[i + 1]; i++ } }
			'-r', '--ref' { if i + 1 < args.len { ref_text = args[i + 1]; i++ } }
			'-p', '--pass' { if i + 1 < args.len { password = args[i + 1]; i++ } }
			'-s', '--seed' { if i + 1 < args.len { seed_val = args[i + 1].u64(); i++ } }
			'-f', '--formats' { if i + 1 < args.len { raw_formats = args[i + 1]; i++ } }
			'-ti', '--typo-intensity' { if i + 1 < args.len { typo_intensity = args[i + 1].int(); i++ } }
			'-tc', '--typo-chars' { if i + 1 < args.len { typo_chars = args[i + 1]; i++ } }
			'-km', '--key-map' { if i + 1 < args.len { key_map = args[i + 1]; i++ } }
			'-q', '--qwerty' { use_qwerty = true }
			'-o', '--overwrite' { overwrite = true }
			'-tr', '--transpose' { transpose = true }
			'-map', '--mapping' { if i + 1 < args.len { mapping_str = args[i + 1]; i++ } }
			'-d', '--deobfuscate' { deobfuscate = true }
			'-ni', '--noise-intensity' { if i + 1 < args.len { noise_intensity = args[i + 1].int(); i++ } }
			'-nc', '--noise-chars' { if i + 1 < args.len { noise_chars_str = args[i + 1]; i++ } }
			else {}
		}
	}

	if mode == 'obfuscate' {
		if text_input == '' {
			println('Error: Text is required (-t or --text)')
			return
		}
		if mapping_str == '' {
			println('Error: Mapping string is required (-map or --mapping)')
			return
		}
		m := parse_mapping(mapping_str)
		noise_chars := get_noise_chars(noise_chars_str)

		if deobfuscate {
			result := apply_deobfuscation(text_input, m, noise_chars)
			println('=== DE-OBFUSCATED TEXT ===\n' + result)
		} else {
			result := apply_obfuscation(text_input, m, noise_intensity, noise_chars, seed_val)
			println('=== OBFUSCATED TEXT ===\n' + result)
		}
		return
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
			encrypt_text_stego(message, text_input, password, seed_val, typo_intensity, typo_chars, key_map, use_qwerty, overwrite, transpose) or { println('Encryption failed: ${err}') }
		} else {
			if text_input == '' { println('Error: Carrier text required (-t)'); return }
			decrypt_text_stego(text_input, ref_text, password, seed_val, typo_intensity, typo_chars, key_map, use_qwerty, overwrite, transpose) or { println('Decryption failed: ${err}') }
		}
	} else {
		println('Error: You must provide either --formats (for Number Mode) or --typo-intensity (for Text Mode).')
		print_help()
	}
}
