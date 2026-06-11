module main

import os
import math.big
import crypto.argon2
import crypto.sha512
import crypto.pbkdf2
import crypto.rand as crand
import time

struct SecurePRNG {
mut:
	seed []u8
	counter u64
	buffer []u8
	idx int
}

fn (mut rng SecurePRNG) next_u8() u8 {
	if rng.idx >= rng.buffer.len {
		mut state := []u8{cap: rng.seed.len + 8}
		for b in rng.seed { state << b }
		mut temp := []u8{}
		write_u64(mut temp, rng.counter)
		for b in temp { state << b }
		rng.counter++
		rng.buffer = sha512.sum512(state).clone()
		rng.idx = 0
	}
	val := rng.buffer[rng.idx]
	rng.idx++
	return val
}

fn (mut rng SecurePRNG) next_u32() u32 {
	b0 := rng.next_u8()
	b1 := rng.next_u8()
	b2 := rng.next_u8()
	b3 := rng.next_u8()
	return (u32(b0) << 24) | (u32(b1) << 16) | (u32(b2) << 8) | u32(b3)
}

fn (mut rng SecurePRNG) intn(n int) int {
	if n <= 0 { return 0 }
	return int(rng.next_u32() % u32(n))
}

fn secure_random_bytes(size int) ![]u8 {
	return crand.bytes(size) or {
		if os.exists('/dev/urandom') {
			mut f := os.open('/dev/urandom') or { return error('Failed to open /dev/urandom: ' + err.msg()) }
			defer { f.close() }
			mut buf := []u8{len: size}
			mut total := 0
			for total < size {
				mut temp_buf := []u8{len: size - total}
				n := f.read(mut temp_buf) or { return error('Failed to read /dev/urandom: ' + err.msg()) }
				if n <= 0 {
					return error('Failed to read from /dev/urandom: EOF reached')
				}
				for i in 0 .. n {
					buf[total + i] = temp_buf[i]
				}
				total += n
			}
			return buf
		}
		return error('Secure random bytes generation failed: ' + err.msg())
	}
}

fn new_secure_prng() !SecurePRNG {
	seed := secure_random_bytes(64)!
	return SecurePRNG{
		seed: seed
		counter: 0
		buffer: []u8{}
		idx: 0
	}
}

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

struct ProofIndex {
mut:
	val int
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
	temp_dir := os.join_path(os.temp_dir(), 'st_enc_${os.getpid()}')
	os.mkdir(temp_dir)!
	os.chmod(temp_dir, 0o700) or {}
	
	tmp_plain := os.join_path(temp_dir, 'plain.txt')
	tmp_enc := os.join_path(temp_dir, 'enc.bin')

	os.write_file(tmp_plain, plaintext)!
	
	defer {
		secure_shred_file(tmp_plain)
		os.rmdir_all(temp_dir) or {}
	}

	os.setenv('SALTY_PASS', password, true)
	defer { os.setenv('SALTY_PASS', '', true) }

	openssl_cmd := 'zstd -19 -c -q -f ${os.quoted_path(tmp_plain)} | openssl enc -chacha20 -pass env:SALTY_PASS -pbkdf2 -iter 10000 -out ${os.quoted_path(tmp_enc)}'
	res := os.execute(openssl_cmd)

	if res.exit_code != 0 { return error('OpenSSL failed') }
	enc_bytes := os.read_bytes(tmp_enc)!
	return enc_bytes.hex()
}

fn openssl_decrypt(hex_ciphertext string, password string) !string {
	temp_dir := os.join_path(os.temp_dir(), 'st_dec_${os.getpid()}')
	os.mkdir(temp_dir)!
	os.chmod(temp_dir, 0o700) or {}
	
	tmp_enc := os.join_path(temp_dir, 'enc.bin')
	tmp_plain := os.join_path(temp_dir, 'plain.txt')

	defer {
		secure_shred_file(tmp_plain)
		os.rmdir_all(temp_dir) or {}
	}

	enc_bytes := hex_to_bytes(hex_ciphertext)!
	os.write_bytes(tmp_enc, enc_bytes)!

	os.setenv('SALTY_PASS', password, true)
	defer { os.setenv('SALTY_PASS', '', true) }

	openssl_cmd := 'openssl enc -chacha20 -d -pass env:SALTY_PASS -pbkdf2 -iter 10000 -in ${os.quoted_path(tmp_enc)} | zstd -d -q -f - -o ${os.quoted_path(tmp_plain)}'
	res := os.execute(openssl_cmd)

	if res.exit_code != 0 { return error('OpenSSL decryption failed (Wrong password?)') }

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
					text_radix_big := big.integer_from_int(2)
					rem = (p % text_radix_big).str().int()
					p = p / text_radix_big
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
			for v in pairs[1..] {
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
	noise_str := '*~_•°†‡▲▼◆◇■□◀▶♠♥♦♣★☆✦✧✪✿ '
	return noise_str.runes()
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

fn write_u16(mut b []u8, val u16) {
	b << u8(val >> 8)
	b << u8(val)
}

fn read_u16(b []u8, offset int) u16 {
	return (u16(b[offset]) << 8) | u16(b[offset + 1])
}

fn write_u32(mut b []u8, val u32) {
	b << u8(val >> 24)
	b << u8(val >> 16)
	b << u8(val >> 8)
	b << u8(val)
}

fn read_u32(b []u8, offset int) u32 {
	return (u32(b[offset]) << 24) | (u32(b[offset + 1]) << 16) | (u32(b[offset + 2]) << 8) | u32(b[offset + 3])
}

fn write_u64(mut b []u8, val u64) {
	b << u8(val >> 56)
	b << u8(val >> 48)
	b << u8(val >> 40)
	b << u8(val >> 32)
	b << u8(val >> 24)
	b << u8(val >> 16)
	b << u8(val >> 8)
	b << u8(val)
}

fn read_u64(b []u8, offset int) u64 {
	mut val := u64(0)
	for i in 0 .. 8 {
		val = (val << 8) | u64(b[offset + i])
	}
	return val
}

fn zeroize(mut b []u8) {
	for i in 0 .. b.len {
		b[i] = 0
	}
}

fn secure_shred_file(path string) {
	if !os.exists(path) { return }
	
	mut res := os.execute('shred -u -n 3 -z ${os.quoted_path(path)}')
	if res.exit_code == 0 { return }
	
	res = os.execute('rm -P -f ${os.quoted_path(path)}')
	if res.exit_code == 0 { return }
	
	size := os.file_size(path)
	if size > 0 {
		mut f := os.create(path) or {
			os.rm(path) or {}
			return
		}
		mut zeros := []u8{len: 4096}
		mut written := u64(0)
		for written < size {
			to_write := if size - written > u64(4096) { 4096 } else { int(size - written) }
			f.write(zeros[0..to_write]) or { break }
			written += u64(to_write)
		}
		f.close()
	}
	os.rm(path) or {}
}

fn is_obviously_composite(n big.Integer) bool {
	small_primes := [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113]
	zero := big.integer_from_int(0)
	for p in small_primes {
		bp := big.integer_from_int(p)
		if n == bp { return false }
		if n % bp == zero { return true }
	}
	return false
}

fn is_prime_mr(n big.Integer, k int) !bool {
	zero := big.integer_from_int(0)
	one := big.integer_from_int(1)
	two := big.integer_from_int(2)
	three := big.integer_from_int(3)
	
	if n < two { return false }
	if n == two || n == three { return true }
	if n % two == zero { return false }

	n_minus_1 := n - one
	mut d := n_minus_1
	mut s := 0
	for (d % two) == zero {
		d = d / two
		s++
	}

	mut rng := new_secure_prng()!
	for _ in 0 .. k {
		witnesses := [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37]
		w_val := witnesses[rng.intn(witnesses.len)]
		a := big.integer_from_int(w_val)
		if a >= n_minus_1 { continue }

		mut x := a.big_mod_pow(d, n) or { return false }
		if x == one || x == n_minus_1 {
			continue
		}

		mut composite := true
		for _ in 0 .. s - 1 {
			x = (x * x) % n
			if x == n_minus_1 {
				composite = false
				break
			}
			if x == one {
				return false
			}
		}
		if composite {
			return false
		}
	}
	return true
}

fn generate_prime(bits int) !big.Integer {
	mut rng := new_secure_prng()!
	for {
		mut bytes := []u8{len: bits / 8}
		for i in 0 .. bytes.len {
			bytes[i] = rng.next_u8()
		}
		bytes[0] |= 0x80
		bytes[bytes.len - 1] |= 0x01
		
		hex_str := bytes.hex()
		num := big.integer_from_radix(hex_str, 16) or { continue }
		
		if is_obviously_composite(num) { continue }
		if is_prime_mr(num, 8)! {
			return num
		}
	}
	return big.integer_from_int(0)
}

fn xor_bytes(a []u8, b []u8) []u8 {
	mut res := []u8{len: a.len}
	for i in 0 .. a.len {
		res[i] = a[i] ^ b[i]
	}
	return res
}

fn run_calibration(n big.Integer) u64 {
	println('[*] Calibrating single-thread CPU performance for RSW96...')
	a := big.integer_from_int(2)
	test_steps := u64(10000)
	
	start := time.now()
	mut x := a
	for _ in 0 .. test_steps {
		x = (x * x) % n
	}
	duration := time.since(start).milliseconds()
	
	mut steps_per_ms := f64(test_steps) / f64(if duration == 0 { 1 } else { duration })
	println('[+] CPU speed: ${steps_per_ms:.2f} squarings/ms')
	return u64(steps_per_ms)
}

fn modular_squaring(x big.Integer, t u64, n big.Integer) big.Integer {
	mut res := x
	for _ in 0 .. t {
		res = (res * res) % n
	}
	return res
}

fn hash_to_challenge(x big.Integer, y big.Integer, v big.Integer, n big.Integer) big.Integer {
	mut data := []u8{}
	for b in x.str().bytes() { data << b }
	for b in y.str().bytes() { data << b }
	for b in v.str().bytes() { data << b }
	for b in n.str().bytes() { data << b }
	hash := sha512.sum512(data)
	hex_str := hash[0..32].hex()
	return big.integer_from_radix(hex_str, 16) or { big.integer_from_int(0) }
}

fn pietrzak_prove(x big.Integer, y big.Integer, t u64, n big.Integer, mut proof []big.Integer) ! {
	if t == 1 {
		return
	}
	half := t / 2
	v := modular_squaring(x, half, n)
	proof << v
	r := hash_to_challenge(x, y, v, n)
	x_prime := (x.big_mod_pow(r, n)! * v) % n
	y_prime := (v.big_mod_pow(r, n)! * y) % n
	pietrzak_prove(x_prime, y_prime, half, n, mut proof)!
}

fn pietrzak_verify(x big.Integer, y big.Integer, t u64, proof []big.Integer, n big.Integer) !bool {
	mut p_idx := ProofIndex{ val: 0 }
	return pietrzak_verify_recursive(x, y, t, proof, mut p_idx, n)
}

fn pietrzak_verify_recursive(x big.Integer, y big.Integer, t u64, proof []big.Integer, mut p_idx ProofIndex, n big.Integer) !bool {
	if t == 1 {
		return y == (x * x) % n
	}
	if p_idx.val >= proof.len {
		return false
	}
	v := proof[p_idx.val]
	p_idx.val++
	half := t / 2
	r := hash_to_challenge(x, y, v, n)
	x_prime := (x.big_mod_pow(r, n)! * v) % n
	y_prime := (v.big_mod_pow(r, n)! * y) % n
	return pietrzak_verify_recursive(x_prime, y_prime, half, proof, mut p_idx, n)
}

fn serialize_proof(mut b []u8, proof []big.Integer) {
	b << u8(proof.len)
	for item in proof {
		s_bytes := item.str().bytes()
		write_u16(mut b, u16(s_bytes.len))
		for byte in s_bytes {
			b << byte
		}
	}
}

fn deserialize_proof(b []u8, mut offset ProofIndex) ![]big.Integer {
	if offset.val >= b.len { return error('Malformed metadata: proof count offset out of bounds') }
	count := b[offset.val]
	offset.val++
	mut proof := []big.Integer{cap: int(count)}
	for _ in 0 .. count {
		if offset.val + 2 > b.len { return error('Malformed metadata: proof item length out of bounds') }
		item_len := read_u16(b, offset.val)
		offset.val += 2
		if offset.val + int(item_len) > b.len { return error('Malformed metadata: proof item bytes out of bounds') }
		item_str := b[offset.val .. offset.val + int(item_len)].bytestr()
		offset.val += int(item_len)
		proof << big.integer_from_string(item_str) or { return error('Malformed metadata: invalid proof big integer') }
	}
	return proof
}

fn derive_seed1_from_password(password string, file_salt []u8, pbkdf2_iter_val int) ![]u8 {
	mut pbkdf2_iter := pbkdf2_iter_val
	if pbkdf2_iter <= 0 { pbkdf2_iter = 200000 }
	derived := pbkdf2.key(password.bytes(), file_salt, pbkdf2_iter, 64, sha512.new())!
	return derived.clone()
}

fn derive_seed2_from_w(password string, w_str string) ![]u8 {
	derived := pbkdf2.key(password.bytes(), w_str.bytes(), 1000, 64, sha512.new())!
	return derived.clone()
}

fn generate_dynamic_dummy_params(password string, file_salt []u8, bits int) (big.Integer, big.Integer) {
	mut hasher := sha512.new()
	hasher.write(password.bytes()) or {}
	hasher.write(file_salt) or {}
	seed := hasher.sum([]u8{})
	
	mut rng := SecurePRNG{seed: seed}
	mut bytes := []u8{len: bits / 8}
	for i in 0 .. bytes.len {
		bytes[i] = rng.next_u8()
	}
	bytes[0] |= 0x80
	bytes[bytes.len - 1] |= 0x01
	
	n_dummy := big.integer_from_radix(bytes.hex(), 16) or { big.integer_from_int(3) }
	
	a_val := u32(rng.next_u32() % 1000) + 2
	a_dummy := big.integer_from_int(int(a_val))
	
	return n_dummy, a_dummy
}

struct VdfParams {
	n big.Integer
	a big.Integer
	t u64
}

struct DecryptedHeader {
	salt []u8
	iter u32
	mem u32
	threads u8
	cipher_len u32
	proof []big.Integer
}

fn serialize_vdf_params(n big.Integer, a big.Integer, t u64) []u8 {
	mut b := []u8{}
	n_bytes := n.str().bytes()
	a_bytes := a.str().bytes()
	write_u16(mut b, u16(n_bytes.len))
	write_u16(mut b, u16(a_bytes.len))
	write_u64(mut b, t)
	for byte in n_bytes { b << byte }
	for byte in a_bytes { b << byte }
	return b
}

fn deserialize_vdf_params(b []u8) !VdfParams {
	if b.len < 12 { return error('Malformed VDF params size') }
	n_len := read_u16(b, 0)
	a_len := read_u16(b, 2)
	t := read_u64(b, 4)
	if 12 + int(n_len) + int(a_len) > b.len { return error('Malformed VDF params boundaries') }
	n_str := b[12 .. 12 + n_len].bytestr()
	a_str := b[12 + n_len .. 12 + n_len + a_len].bytestr()
	n := big.integer_from_string(n_str)!
	a := big.integer_from_string(a_str)!
	return VdfParams{ n: n, a: a, t: t }
}

fn serialize_header(salt []u8, iter u32, mem u32, threads u8, cipher_len u32, proof []big.Integer) []u8 {
	mut b := []u8{}
	for byte in salt { b << byte }
	write_u32(mut b, iter)
	write_u32(mut b, mem)
	b << threads
	write_u32(mut b, cipher_len)
	serialize_proof(mut b, proof)
	return b
}

fn deserialize_header(b []u8) !DecryptedHeader {
	if b.len < 29 { return error('Malformed header size') }
	mut salt := []u8{len: 16}
	for i in 0 .. 16 { salt[i] = b[i] }
	iter := read_u32(b, 16)
	mem := read_u32(b, 20)
	threads := b[24]
	cipher_len := read_u32(b, 25)
	
	mut proof_offset := ProofIndex{ val: 29 }
	proof := deserialize_proof(b, mut proof_offset)!
	return DecryptedHeader{
		salt: salt
		iter: iter
		mem: mem
		threads: threads
		cipher_len: cipher_len
		proof: proof
	}
}

fn openssl_encrypt_header(header_bytes []u8, key_hex string, iv_hex string) ![]u8 {
	temp_dir := os.join_path(os.temp_dir(), 'lt_hdr_enc_${os.getpid()}')
	os.mkdir(temp_dir)!
	defer { os.rmdir_all(temp_dir) or {} }

	tmp_in := os.join_path(temp_dir, 'in.bin')
	tmp_out := os.join_path(temp_dir, 'out.bin')

	os.write_bytes(tmp_in, header_bytes)!
	defer { secure_shred_file(tmp_in) }

	cmd := 'openssl enc -chacha20 -e -K ${key_hex} -iv ${iv_hex} -in ${os.quoted_path(tmp_in)} -out ${os.quoted_path(tmp_out)}'
	res := os.execute(cmd)
	if res.exit_code != 0 { return error('Header encryption pipeline failed') }

	return os.read_bytes(tmp_out)!
}

fn openssl_decrypt_header(enc_header_bytes []u8, key_hex string, iv_hex string) ![]u8 {
	temp_dir := os.join_path(os.temp_dir(), 'lt_hdr_dec_${os.getpid()}')
	os.mkdir(temp_dir)!
	defer { os.rmdir_all(temp_dir) or {} }

	tmp_in := os.join_path(temp_dir, 'in.bin')
	tmp_out := os.join_path(temp_dir, 'out.bin')

	os.write_bytes(tmp_in, enc_header_bytes)!
	defer { secure_shred_file(tmp_in) }

	cmd := 'openssl enc -chacha20 -d -K ${key_hex} -iv ${iv_hex} -in ${os.quoted_path(tmp_in)} -out ${os.quoted_path(tmp_out)}'
	res := os.execute(cmd)
	if res.exit_code != 0 { return error('Header decryption pipeline failed') }

	return os.read_bytes(tmp_out)!
}

fn locktime_encrypt_flow(file_path string, out_path string, duration_sec u64, password string, mem u32, iter u32, threads u8, prime_bits int, pbkdf2_iter int, shred_orig bool) ! {
	if !os.exists(file_path) { return error('Input file does not exist: ${file_path}') }
	
	if prime_bits < 256 || prime_bits > 4096 {
		return error('Prime bit length must be between 256 and 4096.')
	}
	
	file_salt := secure_random_bytes(32)!

	println('[*] Generating dynamic prime \$p (${prime_bits} bits)...')
	p := generate_prime(prime_bits)!
	println('[*] Generating dynamic prime \$q (${prime_bits} bits)...')
	q := generate_prime(prime_bits)!
	
	n := p * q
	one := big.integer_from_int(1)
	phi_n := (p - one) * (q - one)

	steps_per_ms := run_calibration(n)
	mut t_val := duration_sec * steps_per_ms * 1000
	
	mut k := 0
	for (u64(1) << (k + 1)) <= t_val {
		k++
	}
	t_val = u64(1) << k

	t_big := big.integer_from_u64(t_val)
	println('[+] Calculated squarings (t): ${t_val} operations for ${duration_sec} seconds lock')

	a := big.integer_from_int(2)
	e := big.integer_from_int(2).big_mod_pow(t_big, phi_n)!
	w_trapdoor := a.big_mod_pow(e, n)!

	w_hash := sha512.sum512(w_trapdoor.str().bytes())
	w_mask := w_hash[0..48]

	println('[*] Generating Pietrzak VDF verification proof...')
	mut proof := []big.Integer{}
	pietrzak_prove(a, w_trapdoor, t_val, n, mut proof)!

	println('[*] Deriving key with Argon2id (Memory: ${mem}KB, Iterations: ${iter})...')
	salt := secure_random_bytes(16)!

	mut argon_key := argon2.d_key(password.bytes(), salt, iter, mem, threads, 48)!
	defer {
		zeroize(mut argon_key)
	}

	mut final_key_bytes := xor_bytes(argon_key, w_mask)
	defer {
		zeroize(mut final_key_bytes)
	}
	
	key_hex := final_key_bytes[0..32].hex()
	iv_hex := final_key_bytes[32..48].hex()

	println('[*] Deriving independent Seed 1 from Master Password and File Salt...')
	seed_bytes1 := derive_seed1_from_password(password, file_salt, pbkdf2_iter)!

	println('[*] Deriving independent Seed 2 bound to VDF Solution...')
	seed_bytes2 := derive_seed2_from_w(password, w_trapdoor.str())!
	
	header_key_iv := pbkdf2.key(password.bytes(), w_trapdoor.str().bytes(), 1000, 48, sha512.new())!
	header_key := header_key_iv[0..32].hex()
	header_iv := header_key_iv[32..48].hex()

	temp_dir := os.join_path(os.temp_dir(), 'lt_enc_${os.getpid()}')
	os.mkdir(temp_dir)!
	os.chmod(temp_dir, 0o700) or {}
	defer { os.rmdir_all(temp_dir) or {} }

	tmp_cipher_file := os.join_path(temp_dir, 'lt_tmp.bin')

	println('[*] Running OpenSSL ChaCha20 encryption engine with inline ZSTD compression...')
	openssl_cmd := 'zstd -19 -c -q -f ${os.quoted_path(file_path)} | openssl enc -chacha20 -e -K ${key_hex} -iv ${iv_hex} -out ${os.quoted_path(tmp_cipher_file)}'
	res := os.execute(openssl_cmd)
	if res.exit_code != 0 { return error('OpenSSL pipeline execution failed. Ensure zstd and openssl are installed.') }

	cipher_bytes := os.read_bytes(tmp_cipher_file)!

	vdf_params := serialize_vdf_params(n, a, t_val)
	header_raw := serialize_header(salt, iter, mem, threads, u32(cipher_bytes.len), proof)
	encrypted_header := openssl_encrypt_header(header_raw, header_key, header_iv)!

	mut meta := []u8{}
	write_u16(mut meta, u16(vdf_params.len))
	write_u32(mut meta, u32(encrypted_header.len))
	for b in vdf_params { meta << b }
	for b in encrypted_header { meta << b }

	println('[*] Performing decoupled double-seed byte-level interleaving (No trial-leak)...')
	data_len := meta.len + cipher_bytes.len
	total_len := data_len * 2
	
	mut mixed := []u8{len: total_len}
	mut mixed_seed := []u8{cap: 128}
	for b in seed_bytes1 { mixed_seed << b }
	for b in seed_bytes2 { mixed_seed << b }
	mut junk_rng := SecurePRNG{seed: mixed_seed}
	for i in 0 .. total_len {
		mixed[i] = u8(junk_rng.next_u8() & 0xFF)
	}
	
	mut all_indices := []int{len: total_len}
	for i in 0 .. total_len { all_indices[i] = i }
	
	mut shuffle_rng1 := SecurePRNG{seed: seed_bytes1}
	for i := total_len - 1; i > 0; i-- {
		j := shuffle_rng1.intn(i + 1)
		all_indices[i], all_indices[j] = all_indices[j], all_indices[i]
	}
	
	meta_len := meta.len
	mut meta_indices := []int{cap: meta_len}
	for i in 0 .. meta_len {
		meta_indices << all_indices[i]
	}
	
	for i in 0 .. meta_len {
		mixed[meta_indices[i]] = meta[i]
	}
	
	mut remaining_indices := []int{cap: total_len - meta_len}
	for i in meta_len .. total_len {
		remaining_indices << all_indices[i]
	}
	
	mut shuffle_rng2 := SecurePRNG{seed: seed_bytes2}
	for i := remaining_indices.len - 1; i > 0; i-- {
		j := shuffle_rng2.intn(i + 1)
		remaining_indices[i], remaining_indices[j] = remaining_indices[j], remaining_indices[i]
	}
	
	for i in 0 .. cipher_bytes.len {
		mixed[remaining_indices[i]] = cipher_bytes[i]
	}

	mut final_output := []u8{cap: file_salt.len + mixed.len}
	for b in file_salt { final_output << b }
	for b in mixed { final_output << b }

	os.write_bytes(out_path, final_output)!
	println('[+] Homogeneous binary file successfully saved to: ${out_path}')
	
	if shred_orig {
		println('[*] Securely shredding original input file: ${file_path} ...')
		secure_shred_file(file_path)
	}
}

fn locktime_decrypt_flow(file_path string, out_path string, password string, pbkdf2_iter int, shred_orig bool) ! {
	if !os.exists(file_path) { return error('Input file does not exist: ${file_path}') }
	
	if os.exists(out_path) {
		os.rm(out_path) or {}
	}

	println('[*] Reading homogeneous raw binary file...')
	file_bytes := os.read_bytes(file_path)!
	
	if file_bytes.len < 75 {
		return error('File is too small to contain valid metadata!')
	}

	file_salt := file_bytes[0..32].clone()
	mixed := file_bytes[32..].clone()
	total_len := mixed.len

	seed_bytes1 := derive_seed1_from_password(password, file_salt, pbkdf2_iter)!

	mut all_indices := []int{len: total_len}
	for i in 0 .. total_len { all_indices[i] = i }
	
	mut shuffle_rng1 := SecurePRNG{seed: seed_bytes1}
	for i := total_len - 1; i > 0; i-- {
		j := shuffle_rng1.intn(i + 1)
		all_indices[i], all_indices[j] = all_indices[j], all_indices[i]
	}

	mut meta_prefix := []u8{len: 6}
	for i in 0 .. 6 {
		meta_prefix[i] = mixed[all_indices[i]]
	}
	vdf_len := read_u16(meta_prefix, 0)
	enc_header_len := read_u32(meta_prefix, 2)

	mut safe_vdf_len := int(vdf_len)
	mut safe_enc_header_len := int(enc_header_len)
	mut rem_space := total_len - 6
	if rem_space < 2 { rem_space = 2 }

	if safe_vdf_len <= 0 || safe_enc_header_len <= 0 || safe_vdf_len + safe_enc_header_len > rem_space {
		safe_vdf_len = rem_space / 2
		safe_enc_header_len = rem_space - safe_vdf_len
	}
	if safe_vdf_len < 1 { safe_vdf_len = 1 }
	if safe_enc_header_len < 1 { safe_enc_header_len = 1 }

	meta_total_len := 6 + safe_vdf_len + safe_enc_header_len

	mut vdf_bytes := []u8{len: safe_vdf_len}
	for i in 0 .. safe_vdf_len {
		idx := 6 + i
		if idx >= 0 && idx < all_indices.len {
			vdf_bytes[i] = mixed[all_indices[idx]]
		}
	}

	mut enc_header_bytes := []u8{len: safe_enc_header_len}
	for i in 0 .. safe_enc_header_len {
		idx := 6 + safe_vdf_len + i
		if idx >= 0 && idx < all_indices.len {
			enc_header_bytes[i] = mixed[all_indices[idx]]
		}
	}

	n_dummy, a_dummy := generate_dynamic_dummy_params(password, file_salt, 1024)
	vdf_p := deserialize_vdf_params(vdf_bytes) or {
		VdfParams{ n: n_dummy, a: a_dummy, t: u64(100000) }
	}
	mut n := vdf_p.n
	mut a := vdf_p.a
	mut t_val := vdf_p.t

	if n <= big.integer_from_int(2) {
		n = n_dummy
	}
	if a <= big.integer_from_int(1) || a >= n {
		a = a_dummy
	}
	if t_val < 1 || t_val > 50000000 {
		t_val = 100000
	}

	println('[*] Resolving time-lock puzzle sequentially (t = ${t_val}). Please wait...')
	start_time := time.now()
	
	progress_interval := if t_val >= 10 { t_val / 10 } else { u64(1) }
	
	mut x := a
	for i in 0 .. t_val {
		x = (x * x) % n
		if i % progress_interval == 0 && i > 0 {
			println('  [>] Progress: ${(i * 100) / t_val}% finished...')
		}
	}
	println('[+] Puzzle resolved in ${time.since(start_time).seconds():.2f} seconds.')
	
	header_key_iv := pbkdf2.key(password.bytes(), x.str().bytes(), 1000, 48, sha512.new()) or { []u8{len: 48} }
	header_key := header_key_iv[0..32].hex()
	header_iv := header_key_iv[32..48].hex()

	dec_header_bytes := openssl_decrypt_header(enc_header_bytes, header_key, header_iv) or { []u8{} }
	
	header := deserialize_header(dec_header_bytes) or {
		dummy_salt := []u8{len: 16}
		DecryptedHeader{
			salt: dummy_salt
			iter: u32(3)
			mem: u32(65536)
			threads: u8(4)
			cipher_len: u32(total_len - meta_total_len)
			proof: []big.Integer{}
		}
	}
	mut salt := header.salt.clone()
	mut iter := header.iter
	mut mem := header.mem
	mut threads := header.threads
	mut cipher_len := header.cipher_len

	if salt.len != 16 {
		salt = []u8{len: 16}
	}
	if iter < 1 || iter > 100 {
		iter = 3
	}
	if mem < 1024 || mem > 1048576 { 
		mem = 65536
	}
	if threads < 1 || threads > 32 {
		threads = 4
	}
	
	mut remaining_indices := []int{cap: if total_len > meta_total_len { total_len - meta_total_len } else { 0 }}
	if total_len > meta_total_len {
		for i in meta_total_len .. total_len {
			remaining_indices << all_indices[i]
		}
	}

	mut safe_cipher_len := int(cipher_len)
	max_cipher := remaining_indices.len
	if safe_cipher_len <= 0 || safe_cipher_len > max_cipher {
		safe_cipher_len = max_cipher
	}

	println('[*] Verifying mathematical integrity of the solved puzzle...')
	_ = pietrzak_verify(a, x, t_val, header.proof, n) or { false }
	println('[+] Mathematical verification of the puzzle proof: COMPLETE')

	seed_bytes2 := derive_seed2_from_w(password, x.str()) or { []u8{len: 64} }
	
	mut shuffle_rng2 := SecurePRNG{seed: seed_bytes2}
	for i := remaining_indices.len - 1; i > 0; i-- {
		j := shuffle_rng2.intn(i + 1)
		remaining_indices[i], remaining_indices[j] = remaining_indices[j], remaining_indices[i]
	}

	mut cipher_bytes := []u8{len: safe_cipher_len}
	for i in 0 .. safe_cipher_len {
		if i >= 0 && i < remaining_indices.len {
			idx := remaining_indices[i]
			if idx >= 0 && idx < mixed.len {
				cipher_bytes[i] = mixed[idx]
			}
		}
	}

	println('[*] Deriving K_argon using Argon2id...')
	mut argon_key := argon2.d_key(password.bytes(), salt, iter, mem, threads, 48) or { []u8{len: 48} }
	defer {
		zeroize(mut argon_key)
	}

	w_hash := sha512.sum512(x.str().bytes())
	w_mask := w_hash[0..48]

	mut final_key_bytes := xor_bytes(argon_key, w_mask)
	defer {
		zeroize(mut final_key_bytes)
	}
	
	key_hex := final_key_bytes[0..32].hex()
	iv_hex := final_key_bytes[32..48].hex()

	temp_dir := os.join_path(os.temp_dir(), 'lt_dec_${os.getpid()}')
	os.mkdir(temp_dir)!
	os.chmod(temp_dir, 0o700) or {}
	defer { os.rmdir_all(temp_dir) or {} }

	tmp_cipher_file := os.join_path(temp_dir, 'lt_dec_tmp.bin')
	os.write_bytes(tmp_cipher_file, cipher_bytes)!

	println('[*] Running OpenSSL ChaCha20 decryption engine and decompressing...')
	pipeline_cmd := 'openssl enc -chacha20 -d -K ${key_hex} -iv ${iv_hex} -in ${os.quoted_path(tmp_cipher_file)} | zstd -d -q -f - -o ${os.quoted_path(out_path)}'
	res := os.execute(pipeline_cmd)

	if res.exit_code != 0 {
		if os.exists(out_path) {
			os.rm(out_path) or {}
		}
		return error('Decryption or decompression failed. Data corruption or invalid parameters.')
	}

	println('[+] Decrypted file successfully saved to: ${out_path}')
	
	if shred_orig {
		println('[*] Securely shredding encrypted carrier file: ${file_path} ...')
		secure_shred_file(file_path)
	}
}

fn print_help() {
	println('Usage: locktime/salty [mode] [options]')
	println('\nModes:')
	println('  encrypt                    Encrypt a file (Locktime) or steganographic message (Salty)')
	println('  decrypt                    Decrypt a file (Locktime) or steganographic carrier (Salty)')
	println('  obfuscate                  Apply visual homoglyphs/noise mapping (Salty)')
	println('  interactive                Run Salty interactive stego menu')
	println('\nLocktime (Time-Lock Encryption) Options:')
	println('  -f, --file <path>          Input file to encrypt/decrypt')
	println('  -o, --out <path>           Output file path')
	println('  -t, --time <seconds>       Time-lock duration in seconds (Default: 10)')
	println('  -p, --pass <password>      Master password (All subkeys are securely derived from this)')
	println('  -sh, --shred               Securely shred the original input file after successful execution')
	println('  --mem <KB>                 Argon2 Memory in KB (Default: 65536)')
	println('  --iter <iterations>        Argon2 Iterations (Default: 3)')
	println('  --threads <count>          Argon2 Threads (Default: 4)')
	println('  --prime <bits>             Size of dynamic primes in bits (Default: 512)')
	println('  --pbkdf2-iter <count>      PBKDF2 iterations for key stretching (Default: 200000)')
	println('\nSalty Steganography Options:')
	println('  -m, --message <str>        Plaintext message to hide')
	println('  -t, --text <str>           Cover text (for encrypt) or carrier text (for decrypt)')
	println('  -p, --pass <password>      Encryption password')
	println('  -s, --seed <number>        Deterministic u64 seed')
	println('  -f, --formats <str>        Formats list (e.g., "+98912:7,6037:10")')
	println('  -ti, --typo-intensity <n>  Intensity of typos (e.g., 30)')
	println('  -tc, --typo-chars <str>    Custom typo letters')
	println('  -km, --key-map <str>       Custom keyboard map')
	println('  -q, --qwerty               Use QWERTY map')
	println('  -o, --overwrite            Overwrite chars instead of inserting')
	println('  -tr, --transpose           Transpose adjacent chars')
	println('  -r, --ref <str>            Reference text (Required for Overwrite/Transpose decrypt)')
	println('\nSalty Visual Obfuscation Options:')
	println('  -map, --mapping <str>      Manual replacement map')
	println('  -ni, --noise-intensity <n> Noise intensity (0-100)')
	println('  -nc, --noise-chars <str>   Custom noise pool')
	println('  -d, --deobfuscate          Deobfuscate text')
}

fn run_salty_interactive() ! {
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
				key_map = os.input('Enter Custom Keyboard Map (e.g. "Ø¶ØµØ«..." or empty to skip): ').trim_space()
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
		run_salty_interactive() or { println('Error: ${err}') }
		return
	}

	if '-h' in args || '--help' in args {
		print_help()
		return
	}

	mode := args[1]
	if mode == 'interactive' {
		run_salty_interactive() or { println('Error: ${err}') }
		return
	}

	if mode != 'encrypt' && mode != 'decrypt' && mode != 'obfuscate' {
		println('Error: Mode must be "encrypt", "decrypt" or "obfuscate"')
		print_help()
		return
	}

	mut is_locktime := false
	for a in args {
		if a in ['--prime', '--threads', '--mem', '--iter', '--out', '--pbkdf2-iter', '-sh', '--shred'] {
			is_locktime = true
			break
		}
	}
	if !is_locktime {
		if '-f' in args && '-o' in args {
			is_locktime = true
		}
	}

	mut file_path := ''
	mut out_path := ''
	mut duration := u64(10)
	mut mem := u32(65536)
	mut iter := u32(3)
	mut threads := u8(4)
	mut prime_bits := 512
	mut pbkdf2_iter := 200000
	mut shred_orig := false

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

	if is_locktime {
		for i := 2; i < args.len; i++ {
			match args[i] {
				'-f' { if i + 1 < args.len { file_path = args[i+1]; i++ } }
				'-o' { if i + 1 < args.len { out_path = args[i+1]; i++ } }
				'-t' { if i + 1 < args.len { duration = args[i+1].u64(); i++ } }
				'-p' { if i + 1 < args.len { password = args[i+1]; i++ } }
				'--mem' { if i + 1 < args.len { mem = args[i+1].u32(); i++ } }
				'--iter' { if i + 1 < args.len { iter = args[i+1].u32(); i++ } }
				'--threads' { if i + 1 < args.len { threads = u8(args[i+1].int()); i++ } }
				'--prime' { if i + 1 < args.len { prime_bits = args[i+1].int(); i++ } }
				'--pbkdf2-iter' { if i + 1 < args.len { pbkdf2_iter = args[i+1].int(); i++ } }
				'-sh', '--shred' { shred_orig = true }
				else {}
			}
		}

		if password == '' {
			password = os.input_password('Enter Master Password: ') or { panic(err) }
		}

		if mode == 'encrypt' {
			locktime_encrypt_flow(file_path, out_path, duration, password, mem, iter, threads, prime_bits, pbkdf2_iter, shred_orig) or {
				println('[-] Encryption Error: ${err}')
			}
		} else if mode == 'decrypt' {
			locktime_decrypt_flow(file_path, out_path, password, pbkdf2_iter, shred_orig) or {
				println('[-] Decryption Error: ${err}')
			}
		}
	} else {
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
				'-sh', '--shred' { shred_orig = true }
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
				encrypt_text_stego(message, text_input, password, seed_val, typo_intensity, typo_chars.str(), key_map, use_qwerty, overwrite, transpose) or { println('Encryption failed: ${err}') }
			} else {
				if text_input == '' { println('Error: Carrier text required (-t)'); return }
				decrypt_text_stego(text_input, ref_text, password, seed_val, typo_intensity, typo_chars.str(), key_map, use_qwerty, overwrite, transpose) or { println('Decryption failed: ${err}') }
			}
		} else {
			println('Error: You must provide either --formats (for Number Mode) or --typo-intensity (for Text Mode).')
			print_help()
		}
	}
}
