module main

import os
import term
import math.big
import crypto.argon2
import crypto.sha3
import crypto.rand as crand
import time
import x.crypto.chacha20
import x.crypto.chacha20poly1305
import compress.zstd
fn C.memset(ptr voidptr, val int, size usize) voidptr

fn C.mlock(addr voidptr, len usize) int
fn C.munlock(addr voidptr, len usize) int
fn C.VirtualLock(addr voidptr, len usize) int
fn C.VirtualUnlock(addr voidptr, len usize) int

fn lock_memory(mut b []u8) {
    if b.len == 0 { return }
    unsafe {
        $if windows {
            C.VirtualLock(b.data, b.len)
        } $else {
            C.mlock(b.data, b.len)
        }
    }
}

fn unlock_memory(mut b []u8) {
    if b.len == 0 { return }
    unsafe {
        $if windows {
            C.VirtualUnlock(b.data, b.len)
        } $else {
            C.munlock(b.data, b.len)
        }
    }
}

fn encode_to_seed0(val u32, key_seed0 []u8, idx u32) []u8 {
    mut ctx := []u8{len: 4}
    ctx[0] = u8(idx >> 24)
    ctx[1] = u8(idx >> 16)
    ctx[2] = u8(idx >> 8)
    ctx[3] = u8(idx)

    mut hash_input := []u8{cap: key_seed0.len + 4}
    for b in key_seed0 { hash_input << b }
    for b in ctx { hash_input << b }

    keystream := sha3.sum512(hash_input)

    mut buf := []u8{len: 32}
    buf[0] = u8(val >> 24) ^ keystream[0]
    buf[1] = u8(val >> 16) ^ keystream[1]
    buf[2] = u8(val >> 8) ^ keystream[2]
    buf[3] = u8(val) ^ keystream[3]

    for i in 4 .. 32 {
        buf[i] = keystream[i]
    }
    return buf
}

fn decode_from_seed0(target_hash []u8, key_seed0 []u8, idx u32, param_name string) !u32 {
    _ = param_name
    mut ctx := []u8{len: 4}
    ctx[0] = u8(idx >> 24)
    ctx[1] = u8(idx >> 16)
    ctx[2] = u8(idx >> 8)
    ctx[3] = u8(idx)

    mut hash_input := []u8{cap: key_seed0.len + 4}
    for b in key_seed0 { hash_input << b }
    for b in ctx { hash_input << b }

    keystream := sha3.sum512(hash_input)

    b0 := target_hash[0] ^ keystream[0]
    b1 := target_hash[1] ^ keystream[1]
    b2 := target_hash[2] ^ keystream[2]
    b3 := target_hash[3] ^ keystream[3]

    return (u32(b0) << 24) | (u32(b1) << 16) | (u32(b2) << 8) | b3
}

fn hmac_sha3_512(key []u8, message []u8) []u8 {
	block_size := 72
	mut k := []u8{len: block_size, init: 0}
	
	if key.len > block_size {
		hashed_key := sha3.sum512(key)
		for i in 0 .. hashed_key.len {
			k[i] = hashed_key[i]
		}
	} else {
		for i in 0 .. key.len {
			k[i] = key[i]
		}
	}

	mut ipad := []u8{len: block_size, init: 0x36}
	mut opad := []u8{len: block_size, init: 0x5c}

	for i in 0 .. block_size {
		ipad[i] ^= k[i]
		opad[i] ^= k[i]
	}
	
	mut inner_data := []u8{cap: block_size + message.len}
	for b in ipad { inner_data << b }
	for b in message { inner_data << b }
	inner_hash := sha3.sum512(inner_data)
	
	mut outer_data := []u8{cap: block_size + inner_hash.len}
	for b in opad { outer_data << b }
	for b in inner_hash { outer_data << b }
	return sha3.sum512(outer_data)
}

fn pbkdf2_sha3_512(password []u8, salt []u8, iter int, key_len int) []u8 {
	hash_len := 64
	num_blocks := (key_len + hash_len - 1) / hash_len
	mut dk := []u8{cap: key_len}

	for block_num := 1; block_num <= num_blocks; block_num++ {
		mut u_data := []u8{cap: salt.len + 4}
		for b in salt { u_data << b }
		u_data << u8(block_num >> 24)
		u_data << u8(block_num >> 16)
		u_data << u8(block_num >> 8)
		u_data << u8(block_num)

		mut u := hmac_sha3_512(password, u_data)
		mut block_xor := u.clone()
		
		for _ in 1 .. iter {
			u = hmac_sha3_512(password, u)
			for j in 0 .. hash_len {
				block_xor[j] ^= u[j]
			}
		}
		
		remaining := key_len - dk.len
		to_copy := if remaining < hash_len { remaining } else { hash_len }
		for j in 0 .. to_copy {
			dk << block_xor[j]
		}
	}
	return dk
}

struct SecurePRNG {
mut:
	seed    []u8
	counter u64
	buffer  []u8
	idx     int
}

fn (mut rng SecurePRNG) next_u8() u8 {
	if rng.idx >= rng.buffer.len {
		mut state := []u8{cap: rng.seed.len + 8}
		for b in rng.seed { state << b }
		mut temp := []u8{}
		write_u64(mut temp, rng.counter)
		for b in temp { state << b }
		rng.counter++
		rng.buffer = sha3.sum512(state).clone()
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
	return (u32(b0) << 24) | (u32(b1) << 16) | (u32(b2) << 8) | b3
}

fn (mut rng SecurePRNG) intn(n int) int {
	if n <= 0 { return 0 }
	limit := u32(-n) % u32(n)
	for {
		r := rng.next_u32()
		if r >= limit {
			return int(r % u32(n))
		}
	}
	return 0
}

fn new_secure_prng_from_string(seed_str string) SecurePRNG {
	hashed := sha3.sum512(seed_str.bytes())
	return SecurePRNG{
		seed: hashed.clone()
		counter: 0
		buffer: []u8{}
		idx: 0
	}
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
				n := f.read(mut temp_buf) or { return error('Failed to read /dev/urandom: EOF reached') }
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

fn get_shuffled_indices(len int, seed string) []int {
	mut indices := []int{len: len}
	for i in 0 .. len { indices[i] = i }
	mut rng := new_secure_prng_from_string(seed)
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

fn encrypt_payload_chacha20(plaintext string, password string, use_compression bool) !string {
	mut payload_bytes := plaintext.bytes()
	if use_compression {
		payload_bytes = zstd.compress(payload_bytes, compression_level: 19, nb_threads: 4)!
	}
	salt := secure_random_bytes(16)!
	key := pbkdf2_sha3_512(password.bytes(), salt, 10000, 32)
	nonce := secure_random_bytes(12)!
	encrypted := chacha20poly1305.encrypt(payload_bytes, key, nonce, []u8{})!
	mut final_bytes := []u8{cap: salt.len + nonce.len + encrypted.len}
	final_bytes << salt
	final_bytes << nonce
	final_bytes << encrypted
	return final_bytes.hex()
}

fn decrypt_payload_chacha20(hex_ciphertext string, password string, use_compression bool) !string {
	raw_data := hex_to_bytes(hex_ciphertext)!
	if raw_data.len < 16 + 12 { return error('Ciphertext too short or corrupted') }
	salt := raw_data[0..16]
	nonce := raw_data[16..28]
	encrypted := raw_data[28..]
	key := pbkdf2_sha3_512(password.bytes(), salt, 10000, 32)
	mut payload_bytes := chacha20poly1305.decrypt(encrypted, key, nonce, []u8{}) or {
		return error('Decryption failed (Wrong password or tampered data)')
	}
	if use_compression {
		payload_bytes = zstd.decompress(payload_bytes) or {
			return error('Decompression failed')
		}
	}
	return payload_bytes.bytestr()
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

fn encrypt_text_stego(message string, cover_text string, password string, seed string, intensity int, typo_chars_str string, key_map_str string, use_qwerty bool, overwrite bool, transpose bool, use_compression bool) ! {
	mut real_overwrite := overwrite
	if transpose {
		real_overwrite = true
	}
	mut real_intensity := intensity
	if real_intensity > 25 {
		println(term.yellow('[!] Warning: Stego intensity capped at 25% to respect Square-Root Law and prevent detection.'))
		real_intensity = 25
	}
	hex_cipher := encrypt_payload_chacha20(message, password, use_compression)!
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
	mut rng := new_secure_prng_from_string(seed)
	runes := cover_text.runes()
	mut modified_text := []rune{}
	mut i := 0
	for i < runes.len {
		ch := runes[i]
		if rng.intn(100) < real_intensity {
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
	println(term.bold(term.cyan('=== STEGANOGRAPHY ENCRYPTION ===')))
	if transpose { println(term.yellow('Mode: TRANSPOSITION (Active)')) }
	if real_overwrite { println(term.cyan('Mode: OVERWRITE (Length preserved)')) } else { println(term.cyan('Mode: INSERTION')) }
	println(term.bold(term.cyan('Carrier text:')))
	println(modified_text.string())
}

fn decrypt_text_stego(modified_text string, ref_text string, password string, seed string, intensity int, typo_chars_str string, key_map_str string, use_qwerty bool, overwrite bool, transpose bool, use_compression bool) ! {
	mut rng := new_secure_prng_from_string(seed)
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
	mut real_intensity := intensity
	if real_intensity > 25 {
		real_intensity = 25
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
			if rng.intn(100) < real_intensity {
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
			if rng.intn(100) < real_intensity {
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
		mut rng_ins := new_secure_prng_from_string(seed)
		mut original_idx := 0
		mut carrier_idx := 0
		mut spot_idx := 0
		for original_idx < original_runes.len {
			ch := original_runes[original_idx]
			carrier_idx++
			if rng_ins.intn(100) < real_intensity {
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
	plaintext := decrypt_payload_chacha20(hex_cipher, password, use_compression)!
	println(term.bold(term.green('=== DECRYPTION ===\n${plaintext}')))
}

fn encrypt_number_flow(message string, password string, seed string, formats []Format, use_compression bool) ! {
	hex_ciphertext := encrypt_payload_chacha20(message, password, use_compression)!
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
			mut rng := new_secure_prng_from_string(seed + '999')
			for _ in 0 .. needed { chunk_data += rng.intn(10).str() }
		}
		chunks << fmt.prefix + chunk_data
		cursor += size
	}
	shuffled_indices := get_shuffled_indices(chunks.len, seed)
	mut proposed := []string{len: chunks.len}
	for i in 0 .. chunks.len { proposed[i] = chunks[shuffled_indices[i]] }
	println(term.bold(term.cyan('=== NUMBER ENCRYPTION ===')))
	println(term.cyan('Proposed obfuscated numbers:'))
	for idx, num in proposed { println('  ' + (idx + 1).str() + ': ' + term.yellow(num)) }
}

fn decrypt_number_flow(carrier_text string, password string, seed string, formats []Format, use_compression bool) ! {
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
	if dec_str.len < 4 {
		return error('Malformed decrypted structure: data is too short')
	}
	payload_len := dec_str[0 .. 4].int()
	if payload_len < 0 || 4 + payload_len > dec_str.len {
		return error('Malformed decrypted structure: payload length out of bounds')
	}
	dec_payload := dec_str[4 .. 4 + payload_len]
	big_int := big.integer_from_string(dec_payload)!
	mut hex_ciphertext := big_int.hex()
	if hex_ciphertext.len % 2 != 0 { hex_ciphertext = '0' + hex_ciphertext }
	plaintext := decrypt_payload_chacha20(hex_ciphertext, password, use_compression)!
	println(term.bold(term.green('=== DECRYPTION ===\n' + plaintext)))
}

fn parse_mapping(raw string) map[string][]string {
	mut m := map[string][]string{}
	if raw == '' { return m }
	pairs := raw.split(',')
	for pair in pairs {
		parts := pair.split(':')
		if parts.len >= 2 {
			key := parts[0].trim_space()
			m[key] = parts[1..].map(it.trim_space())
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
	noise_str := '*~_•°†‡▲▼◆◇■□◀▶♠♥♦♣★☆✦✧✪✿'
	return noise_str.runes()
}

fn apply_obfuscation(text string, m map[string][]string, noise_intensity int, noise_chars []rune, seed string) string {
	mut rng := new_secure_prng_from_string(seed)
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

fn write_u64_to_buf(mut b []u8, val u64, offset int) {
	for b.len < offset + 8 { b << 0 }
	b[offset]     = u8(val >> 56)
	b[offset + 1] = u8(val >> 48)
	b[offset + 2] = u8(val >> 40)
	b[offset + 3] = u8(val >> 32)
	b[offset + 4] = u8(val >> 24)
	b[offset + 5] = u8(val >> 16)
	b[offset + 6] = u8(val >> 8)
	b[offset + 7] = u8(val)
}

fn zeroize(mut b []u8) {
	if b.len == 0 { return }
	for i in 0 .. b.len {
		b[i] = 0
	}
	if b.len > 0 {
		if b[0] != 0 {
			eprintln('Scrub check failed')
		}
	}
}

fn secure_shred_file(path string) {
	if !os.exists(path) { return }
	size := os.file_size(path)
	if size > 0 {
		mut f := os.open_file(path, 'r+', 0o600) or {
			os.rm(path) or {}
			return
		}
		chunk_size := 65536
		mut remaining := size
		for remaining > 0 {
			to_write := if remaining < u64(chunk_size) { int(remaining) } else { chunk_size }
			mut random_data := secure_random_bytes(to_write) or {
				[]u8{len: to_write, init: 0x00}
			}
			f.write(random_data) or {}
			remaining -= u64(to_write)
		}
		f.close()
	}
	os.rm(path) or {}
}

fn xor_bytes(a []u8, b []u8) []u8 {
	mut res := []u8{len: a.len}
	for i in 0 .. a.len {
		res[i] = a[i] ^ b[i]
	}
	return res
}

fn run_sequential_delay(initial_state []u8, t u64, show_progress bool) []u8 {
	mut state := initial_state.clone()
	if t == 0 { return state }
	
	n_blocks := 16384
	mut buf := [][]u8{cap: n_blocks}
	
	mut temp := state.clone()
	for _ in 0 .. n_blocks {
		temp = sha3.sum512(temp).clone()
		buf << temp.clone()
	}
	
	progress_interval := if t >= 10 { t / 10 } else { u64(1) }
	for i in u64(0) .. t {
		mut idx_val := u64(0)
		for j in 0 .. 8 {
			idx_val = (idx_val << 8) | u64(state[j])
		}
		idx := int(idx_val % u64(n_blocks))
		
		mut mix := []u8{cap: 128}
		for b in state { mix << b }
		for b in buf[idx] { mix << b }
		
		state = sha3.sum512(mix).clone()
		buf[idx] = state.clone()
		
		if show_progress && i % progress_interval == 0 && i > 0 {
			println(term.yellow('  [>] Progress: ${(i * 100) / t}% finished...'))
		}
	}
	return state
}

fn derive_seed1(seed_str string, file_salt []u8, pbkdf2_iter_val int) ![]u8 {
	_ = pbkdf2_iter_val
	mut derived := argon2.d_key(seed_str.bytes(), file_salt, 3, 32768, 2, 64)!
	lock_memory(mut derived)
	return derived
}

fn derive_seed2(seed_str string, w_bytes []u8, iter int) ![]u8 {
	_ = iter
	mut derived := argon2.d_key(seed_str.bytes(), w_bytes, 3, 32768, 2, 64)!
	lock_memory(mut derived)
	return derived
}

struct DecryptedHeader {
	salt           []u8
	iter           u32
	mem            u32
	threads        u8
	cipher_len     u32
	key_ciphertext []u8
}

fn serialize_vdf_params(t u64) []u8 {
	mut b := []u8{}
	write_u64(mut b, t)
	return b
}

fn deserialize_vdf_params(b []u8) !u64 {
	if b.len < 8 { return error('Malformed VDF params size') }
	return read_u64(b, 0)
}

fn serialize_header(key_seed0 []u8, t u64, iter u32, mem u32, threads u8, cipher_len u32, key_ciphertext []u8) []u8 {
    mut b := []u8{}
    b << encode_to_seed0(u32(t), key_seed0, 0)
    b << encode_to_seed0(iter, key_seed0, 1)
    b << encode_to_seed0(mem, key_seed0, 2)
    b << encode_to_seed0(u32(threads), key_seed0, 3)
    b << encode_to_seed0(cipher_len, key_seed0, 4)
    
    write_u32(mut b, u32(key_ciphertext.len))
    for byte in key_ciphertext { b << byte }
    return b
}

fn deserialize_header(b []u8, key_seed0 []u8, file_salt []u8) !DecryptedHeader {
    if b.len < 160 { return error('Malformed header size (Seed0 params missing)') }
    
    t_val := decode_from_seed0(b[0..32], key_seed0, 0, 't_param')!
    iter := decode_from_seed0(b[32..64], key_seed0, 1, 'iter')!
    mem := decode_from_seed0(b[64..96], key_seed0, 2, 'mem')!
    threads := u8(decode_from_seed0(b[96..128], key_seed0, 3, 'threads')!)
    cipher_len := decode_from_seed0(b[128..160], key_seed0, 4, 'cipher_len')!
    
    println(term.green('[+] Seed0 Extracted -> T:${t_val}, Iter:${iter}, Mem:${mem}, Len:${cipher_len}'))

    offset := 160
    key_len := read_u32(b, offset)
    
    if u64(b.len) < u64(offset + 4 + int(key_len)) {
        return error('Malformed header key size')
    }
    
    mut key_ciphertext := []u8{len: int(key_len)}
    for i in 0 .. int(key_len) {
        key_ciphertext[i] = b[offset + 4 + i]
    }
    
    return DecryptedHeader{
        salt: file_salt
        iter: iter
        mem: mem
        threads: threads
        cipher_len: cipher_len
        key_ciphertext: key_ciphertext
    }
}

fn openssl_encrypt_header(header_bytes []u8, key_hex string, iv_hex string) ![]u8 {
	key := hex_to_bytes(key_hex)!
	iv := hex_to_bytes(iv_hex)!
	nonce := iv[0..12]
	return chacha20.encrypt(key, nonce, header_bytes)!
}

fn openssl_decrypt_header(enc_header_bytes []u8, key_hex string, iv_hex string) ![]u8 {
	key := hex_to_bytes(key_hex)!
	iv := hex_to_bytes(iv_hex)!
	nonce := iv[0..12]
	return chacha20.decrypt(key, nonce, enc_header_bytes)!
}

fn encrypt_chunk(chunk_data []u8, key []u8, iv []u8, chunk_index u64, use_compression bool) ![]u8 {
	mut data := chunk_data.clone()
	if use_compression {
		data = zstd.compress(data)!
	}
	mut chunk_nonce := []u8{len: 12, init: 0}
	for i in 0 .. 4 { chunk_nonce[i] = iv[i] }
	write_u64_to_buf(mut chunk_nonce, chunk_index, 4)
	return chacha20poly1305.encrypt(data, key, chunk_nonce, []u8{})!
}

fn decrypt_chunk(cipher_bytes []u8, key []u8, iv []u8, chunk_index u64, use_compression bool) ![]u8 {
	mut chunk_nonce := []u8{len: 12, init: 0}
	for i in 0 .. 4 { chunk_nonce[i] = iv[i] }
	write_u64_to_buf(mut chunk_nonce, chunk_index, 4)
	mut decrypted := chacha20poly1305.decrypt(cipher_bytes, key, chunk_nonce, []u8{}) or {
		return error('Chunk decryption failed')
	}
	if use_compression {
		decrypted = zstd.decompress(decrypted)!
	}
	return decrypted
}

fn locktime_encrypt_flow(file_path string, out_path string, duration_sec u64,
password string, seed0_str string, seed1_str string, seed2_str string, mem u32, iter u32, threads
u8, pbkdf2_iter int, shred_orig bool, use_compression bool) ! { 
	if !os.exists(file_path) { return error('Input file does not exist: ${file_path}') } 

	mut infile := os.open(file_path)!
	defer { infile.close() }
	mut outfile := os.create(out_path)!
	defer { outfile.close() }

	file_salt := secure_random_bytes(32)!
	outfile.write(file_salt)!

	mut w_trapdoor_bytes := []u8{}
	
	mut t_val := duration_sec
	if t_val < 2 { t_val = 2 }

	println(term.green('[+] VDF config -> Interleaved Memory-Hard Sequential SHA3-512 Chain (t = ${t_val})'))

	mut data_a := []u8{cap: password.len + file_salt.len}
	for b in password.bytes() { data_a << b }
	for b in file_salt { data_a << b }
	initial_state := sha3.sum512(data_a)

	println(term.cyan('[*] Computing sequential SHA3 chain. Please wait...'))
	w_trapdoor_bytes = run_sequential_delay(initial_state, t_val, true)
	lock_memory(mut w_trapdoor_bytes)
	defer { unlock_memory(mut w_trapdoor_bytes); zeroize(mut w_trapdoor_bytes) }
	
	vdf_params := serialize_vdf_params(t_val)
	mut vdf_size_buf := []u8{}
	write_u16(mut vdf_size_buf, u16(vdf_params.len))
	outfile.write(vdf_size_buf)!
	outfile.write(vdf_params)!
	
	mut header_key_material := []u8{cap: password.len + w_trapdoor_bytes.len}
	for b in password.bytes() { header_key_material << b }
	for b in w_trapdoor_bytes { header_key_material << b }
	
	header_key_iv := pbkdf2_sha3_512(header_key_material, file_salt, pbkdf2_iter, 48)
	header_key := header_key_iv[0..32].hex()
	header_iv := header_key_iv[32..48].hex()

	mut session_key := secure_random_bytes(32)!
	lock_memory(mut session_key)
	defer { unlock_memory(mut session_key); zeroize(mut session_key) }

	mut session_iv := secure_random_bytes(16)!
	lock_memory(mut session_iv)
	defer { unlock_memory(mut session_iv); zeroize(mut session_iv) }

	mut seed_bytes1 := derive_seed1(seed1_str, file_salt, pbkdf2_iter)!
	defer { unlock_memory(mut seed_bytes1); zeroize(mut seed_bytes1) }

	mut seed_bytes2 := derive_seed2(seed2_str, w_trapdoor_bytes, pbkdf2_iter)!
	defer { unlock_memory(mut seed_bytes2); zeroize(mut seed_bytes2) }

	chunk_size := 1024 * 1024
	mut first_chunk_buf := []u8{len: chunk_size}
	n_read := infile.read(mut first_chunk_buf) or { 0 }
	mut first_chunk_raw := []u8{}
	if n_read > 0 { first_chunk_raw = first_chunk_buf[0..n_read].clone() }

	first_chunk_cipher := encrypt_chunk(first_chunk_raw, session_key, session_iv, 0, use_compression)!

	mut key_ciphertext := []u8{}
	
	mut argon_key := argon2.d_key(password.bytes(), file_salt, iter, mem, threads, 48)!
	lock_memory(mut argon_key)
	defer { unlock_memory(mut argon_key); zeroize(mut argon_key) }

	w_hash := sha3.sum512(w_trapdoor_bytes)
	w_mask := w_hash[0..48]
	mut final_key_bytes := xor_bytes(argon_key, w_mask)
	lock_memory(mut final_key_bytes)
	defer { unlock_memory(mut final_key_bytes); zeroize(mut final_key_bytes) }

	mut session_key_iv := []u8{cap: 48}
	for byte in session_key { session_key_iv << byte }
	for byte in session_iv { session_key_iv << byte }
	key_ciphertext = xor_bytes(session_key_iv, final_key_bytes)

	mut key_seed0_salt := []u8{cap: file_salt.len + 8}
	for b in file_salt { key_seed0_salt << b }
	for b in "seed0key".bytes() { key_seed0_salt << b }
	
	mut key_seed0 := argon2.d_key(seed0_str.bytes(), key_seed0_salt, 3, 32768, 2, 32)!
	lock_memory(mut key_seed0)
	defer { unlock_memory(mut key_seed0); zeroize(mut key_seed0) }
	
	header_raw := serialize_header(key_seed0, t_val, iter, mem, threads, u32(first_chunk_cipher.len), key_ciphertext)
	encrypted_header := openssl_encrypt_header(header_raw, header_key, header_iv)!
	
	mut meta := []u8{}
	write_u32(mut meta, u32(encrypted_header.len))
	for b in encrypted_header { meta << b }

	data_len := meta.len + first_chunk_cipher.len
	mut total_len := data_len * 2
	
	if total_len < 262144 {
		total_len = 262144
	}
	
	mut mixed := []u8{len: total_len}
	mut mixed_seed := []u8{cap: 128}
	for b in seed_bytes1 { mixed_seed << b }
	for b in seed_bytes2 { mixed_seed << b }
	mut junk_rng := SecurePRNG{seed: mixed_seed}
	for i in 0 .. total_len { mixed[i] = u8(junk_rng.next_u8() & 0xFF) }

	mut all_indices := []int{len: total_len}
	for i in 0 .. total_len { all_indices[i] = i }
	mut shuffle_rng1 := SecurePRNG{seed: seed_bytes1}
	for i := total_len - 1; i > 0; i-- {
		j := shuffle_rng1.intn(i + 1)
		all_indices[i], all_indices[j] = all_indices[j], all_indices[i]
	}

	meta_len := meta.len
	mut meta_indices := []int{cap: meta_len}
	for i in 0 .. meta_len { meta_indices << all_indices[i] }
	for i in 0 .. meta_len { mixed[meta_indices[i]] = meta[i] }

	mut remaining_indices := []int{cap: total_len - meta_len}
	for i in meta_len .. total_len { remaining_indices << all_indices[i] }
	mut shuffle_rng2 := SecurePRNG{seed: seed_bytes2}
	for i := remaining_indices.len - 1; i > 0; i-- {
		j := shuffle_rng2.intn(i + 1)
		remaining_indices[i], remaining_indices[j] = remaining_indices[j], remaining_indices[i]
	}
	for i in 0 .. first_chunk_cipher.len { mixed[remaining_indices[i]] = first_chunk_cipher[i] }

	mut mixed_size_buf := []u8{}
	write_u32(mut mixed_size_buf, u32(mixed.len))
	outfile.write(mixed_size_buf)!
	outfile.write(mixed)!

	mut chunk_index := u64(1)
	mut buf := []u8{len: chunk_size}
	for {
		n_chunk := infile.read(mut buf) or { 0 }
		if n_chunk <= 0 { break }
		chunk_data := buf[0..n_chunk].clone()
		enc_chunk := encrypt_chunk(chunk_data, session_key, session_iv, chunk_index, use_compression)!
		mut len_buf := []u8{}
		write_u32(mut len_buf, u32(enc_chunk.len))
		outfile.write(len_buf)!
		outfile.write(enc_chunk)!
		chunk_index++
	}

	infile.close()
	outfile.close()
	
	println(term.green('[+] Binary file saved to: ${out_path}'))
	if shred_orig {
		println(term.yellow('[*] Securely shredding original file: ${file_path}...'))
		secure_shred_file(file_path)
	}
}

fn locktime_decrypt_flow(file_path string, out_path string, password string,
seed0_str string, seed1_str string, seed2_str string, pbkdf2_iter int, shred_orig bool,
use_compression bool) ! { 
	if !os.exists(file_path) { return error('Input file does not exist: ${file_path}') } 
	if os.exists(out_path) { os.rm(out_path) or {} }

	mut infile := os.open(file_path)!
	defer { infile.close() }
	mut outfile := os.create(out_path)!
	defer { outfile.close() }

	println(term.cyan('[*] Reading binary file...'))
	mut file_salt := []u8{len: 32}
	n_salt := infile.read(mut file_salt)!
	if n_salt < 32 { return error('File too small to contain a salt!') }
	
	mut vdf_size_buf := []u8{len: 2}
	n_vdf_size := infile.read(mut vdf_size_buf)!
	if n_vdf_size < 2 { return error('Malformed VDF params size.') }
	vdf_len := read_u16(vdf_size_buf, 0)

	mut vdf_bytes := []u8{len: int(vdf_len)}
	n_vdf := infile.read(mut vdf_bytes)!
	if n_vdf < int(vdf_len) { return error('Truncated VDF parameters.') }

	t_val := deserialize_vdf_params(vdf_bytes) or {
		return error('Failed to deserialize VDF parameters: ' + err.msg())
	}
	
	mut data_a := []u8{cap: password.len + file_salt.len}
	for b in password.bytes() { data_a << b }
	for b in file_salt { data_a << b }
	initial_state := sha3.sum512(data_a)

	println(term.cyan('[*] Computing SHA3 delay chain (t = ${t_val}). Please wait...'))
	start_time := time.now()
	
	mut x_bytes := run_sequential_delay(initial_state, t_val, true)
	lock_memory(mut x_bytes)
	defer { unlock_memory(mut x_bytes); zeroize(mut x_bytes) }
	println(term.green('[+] Sequential VDF complete in ${time.since(start_time).seconds():.2f} seconds.'))
	
	mut mixed_size_buf := []u8{len: 4}
	n_size := infile.read(mut mixed_size_buf)!
	if n_size < 4 { return error('File too small to contain mixed size!') }
	mixed_len := read_u32(mixed_size_buf, 0)

	mut mixed := []u8{len: int(mixed_len)}
	n_mixed := infile.read(mut mixed)!
	if n_mixed < int(mixed_len) { return error('Failed to read interleaved block!') }

	total_len := mixed.len
	mut seed_bytes1 := derive_seed1(seed1_str, file_salt, pbkdf2_iter)!
	defer { unlock_memory(mut seed_bytes1); zeroize(mut seed_bytes1) }

	mut all_indices := []int{len: total_len}
	for i in 0 .. total_len { all_indices[i] = i }
	mut shuffle_rng1 := SecurePRNG{seed: seed_bytes1}
	for i := total_len - 1; i > 0; i-- {
		j := shuffle_rng1.intn(i + 1)
		all_indices[i], all_indices[j] = all_indices[j], all_indices[i]
	}

	mut meta_prefix := []u8{len: 4}
	for i in 0 .. 4 { meta_prefix[i] = mixed[all_indices[i]] }
	enc_header_len := read_u32(meta_prefix, 0)

	mut safe_enc_header_len := int(enc_header_len)
	mut rem_space := total_len - 4
	if rem_space < 2 { rem_space = 2 }
	if safe_enc_header_len <= 0 || safe_enc_header_len > rem_space {
		safe_enc_header_len = rem_space
	}
	meta_total_len := 4 + safe_enc_header_len

	mut enc_header_bytes := []u8{len: safe_enc_header_len}
	for i in 0 .. safe_enc_header_len {
		idx := 4 + i
		if idx >= 0 && idx < all_indices.len {
			enc_header_bytes[i] = mixed[all_indices[idx]]
		}
	}
	
	mut header_key_material := []u8{cap: password.len + x_bytes.len}
	for b in password.bytes() { header_key_material << b }
	for b in x_bytes { header_key_material << b }

	header_key_iv := pbkdf2_sha3_512(header_key_material, file_salt, pbkdf2_iter, 48)
	header_key := header_key_iv[0..32].hex()
	header_iv := header_key_iv[32..48].hex()

	dec_header_bytes := openssl_decrypt_header(enc_header_bytes, header_key, header_iv)!

	mut key_seed0_salt := []u8{cap: file_salt.len + 8}
	for b in file_salt { key_seed0_salt << b }
	for b in "seed0key".bytes() { key_seed0_salt << b }
	
	mut key_seed0 := argon2.d_key(seed0_str.bytes(), key_seed0_salt, 3, 32768, 2, 32)!
	lock_memory(mut key_seed0)
	defer { unlock_memory(mut key_seed0); zeroize(mut key_seed0) }
	
	header := deserialize_header(dec_header_bytes, key_seed0, file_salt)!

	mut cipher_len := header.cipher_len
	mut remaining_indices := []int{cap: if total_len > meta_total_len { total_len - meta_total_len } else { 0 }}
	if total_len > meta_total_len {
		for i in meta_total_len .. total_len { remaining_indices << all_indices[i] }
	}
	mut safe_cipher_len := int(cipher_len)
	max_cipher := remaining_indices.len
	if safe_cipher_len <= 0 || safe_cipher_len > max_cipher { safe_cipher_len = max_cipher }

	mut session_key := []u8{}
	mut session_iv := []u8{}
	
	mut argon_key := argon2.d_key(password.bytes(), header.salt, header.iter, header.mem, header.threads, 48) or { []u8{len: 48} }
	lock_memory(mut argon_key)
	defer { unlock_memory(mut argon_key); zeroize(mut argon_key) }

	w_hash := sha3.sum512(x_bytes)
	w_mask := w_hash[0..48]
	mut final_key_bytes := xor_bytes(argon_key, w_mask)
	lock_memory(mut final_key_bytes)
	defer { unlock_memory(mut final_key_bytes); zeroize(mut final_key_bytes) }

	if header.key_ciphertext.len != 48 { return error('Malformed classic header ciphertext length') }
	dec_key_iv := xor_bytes(header.key_ciphertext, final_key_bytes)

	session_key = dec_key_iv[0..32].clone()
	lock_memory(mut session_key)
	defer { unlock_memory(mut session_key); zeroize(mut session_key) }

	session_iv = dec_key_iv[32..48].clone()
	lock_memory(mut session_iv)
	defer { unlock_memory(mut session_iv); zeroize(mut session_iv) }

	mut seed_bytes2 := derive_seed2(seed2_str, x_bytes, pbkdf2_iter) or { []u8{len: 64} }
	defer { unlock_memory(mut seed_bytes2); zeroize(mut seed_bytes2) }

	mut shuffle_rng2 := SecurePRNG{seed: seed_bytes2}
	for i := remaining_indices.len - 1; i > 0; i-- {
		j := shuffle_rng2.intn(i + 1)
		remaining_indices[i], remaining_indices[j] = remaining_indices[j], remaining_indices[i]
	}

	mut first_chunk_cipher := []u8{len: safe_cipher_len}
	for i in 0 .. safe_cipher_len {
		if i >= 0 && i < remaining_indices.len {
			idx := remaining_indices[i]
			if idx >= 0 && idx < mixed.len { first_chunk_cipher[i] = mixed[idx] }
		}
	}

	println(term.cyan('[*] Decrypting payload chunks...'))
	first_chunk_raw := decrypt_chunk(first_chunk_cipher, session_key, session_iv, 0, use_compression) or {
		return error('First chunk decryption failed. Data corrupted or wrong parameters.')
	}
	outfile.write(first_chunk_raw)!

	mut chunk_index := u64(1)
	for {
		mut chunk_len_buf := []u8{len: 4}
		n_len := infile.read(mut chunk_len_buf) or { 0 }
		if n_len < 4 { break }
		enc_len := read_u32(chunk_len_buf, 0)
		
		mut enc_chunk := []u8{len: int(enc_len)}
		n_chunk := infile.read(mut enc_chunk)!
		if n_chunk < int(enc_len) { return error('Malformed file: truncated chunk!') }
		
		dec_chunk := decrypt_chunk(enc_chunk, session_key, session_iv, chunk_index, use_compression)!
		outfile.write(dec_chunk)!
		chunk_index++
	}

	infile.close()
	outfile.close()
	
	println(term.green('[+] Decrypted file saved to: ${out_path}'))
	if shred_orig {
		println(term.yellow('[*] Securely shredding encrypted carrier file: ${file_path}...'))
		secure_shred_file(file_path)
	}
}

fn print_help() {
	println(term.bold(term.cyan('Usage: locktime/salty [mode] [options]')))
	println('\nModes:')
	println('  encrypt                    Encrypt a file (Locktime) or steganographic message (Salty)')
	println('  decrypt                    Decrypt a file (Locktime) or steganographic carrier (Salty)')
	println('  obfuscate                  Apply visual homoglyphs/noise mapping (Salty)')
	println('  interactive                Run Salty interactive stego menu')
	println('\nLocktime (Time-Lock Encryption) Options:')
	println('  -f, --file <path>          Input file to encrypt/decrypt')
	println('  -o, --out <path>           Output file path')
	println('  -t, --time <iterations>    Direct VDF iteration count (Default: 100000)')
	println('  -p, --pass <password>      Master password for ChaCha20/Header encryption')
	println('  -s0, --seed0 <str>         Independent password/seed to map and lock VDF metadata')
	println('  -s1, --seed1 <str>         Independent password/seed to map the VDF blocks')
	println('  -s2, --seed2 <str>         Independent password/seed to map the payload blocks')
	println('  -sh, --shred               Securely shred the original input file after successful execution')
	println('  -c, --compress             Enable compression (In-memory zstd)')
	println('  --mem <KB>                 Argon2 Memory in KB (Default: 65536)')
	println('  --iter <iterations>        Argon2 Iterations (Default: 3)')
	println('  --threads <count>          Argon2 Threads (Default: 4)')
	println('  --pbkdf2-iter <count>      PBKDF2 iterations for structural key stretching (Default: 200000)')
	println('\nSalty Steganography Options:')
	println('  -m, --message <str>        Plaintext message to hide')
	println('  -t, --text <str>           Cover text (for encrypt) or carrier text (for decrypt)')
	println('  -r, --ref <str>            Original Reference text (Required for Overwrite/Transpose Dec)')
	println('  -p, --pass <password>      Cryptographic password')
	println('  -s, --seed <str>           Deterministic RNG seed for positions and choices')
	println('  -f, --formats <str>        Layouts for Number Mode (e.g., "+98912:7,6037:10")')
	println('  -ti, --typo-intensity <n>  Typo/Swap frequency percentage (1-100)')
	println('  -tc, --typo-chars <str>    Custom typo letters')
	println('  -km, --key-map <str>       Custom keyboard map')
	println('  -q, --qwerty               Standard US-QWERTY proximity logic')
	println('  -o, --overwrite            Overwrites characters instead of inserting')
	println('  -tr, --transpose           Swaps adjacent letters instead of replacing them')
	println('  -c, --compress             Enable compression (In-memory zstd)')
}

fn run_salty_interactive() ! {
	println(term.bold(term.cyan('=== SALTY INTERACTIVE MODE ===')))
	method := os.input('Choose Carrier Method (1: Fake Numbers, 2: Text Typos, 3: Custom Manual Obfuscation): ').trim_space()
	if method == '1' || method == '2' {
		mode := os.input('Choose Action (1: Encrypt, 2: Decrypt): ').trim_space()
		password := os.input_password('Enter Password: ')!
		compress_ans := os.input('Use compression? (y/n): ').trim_space().to_lower()
		use_compression := compress_ans == 'y'
		if method == '1' {
			formats := parse_formats(os.input('Enter Formats (e.g. "+98912:7,603799:10"): ').trim_space())!
			seed_val := os.input('Enter Seed (string or number): ').trim_space()
			if mode == '1' {
				msg := os.input('Enter Message to encrypt: ')
				encrypt_number_flow(msg, password, seed_val, formats, use_compression)!
			} else {
				txt := os.input('Enter Carrier Text to decrypt: ')
				decrypt_number_flow(txt, password, seed_val, formats, use_compression)!
			}
		} else {
			seed_val := os.input('Enter Typo Seed (string or number): ').trim_space()
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
				key_map = os.input('Enter Custom Keyboard Map or empty to skip: ').trim_space()
				if key_map == '' { typo_chars = os.input('Enter Custom Typo Chars (e.g. "a,b,c" or empty): ').trim_space() }
			}
			if mode == '1' {
				msg := os.input('Enter Message to encrypt: ')
				cover := os.input('Enter Reference Text (The text to hide payload inside): ')
				encrypt_text_stego(msg, cover, password, seed_val, intensity, typo_chars, key_map, use_qwerty, overwrite, transpose, use_compression)!
			} else {
				carrier := os.input('Enter the Carrier text: ')
				mut ref_text := ''
				if overwrite || transpose {
					ref_text = os.input('Enter ORIGINAL Reference Text: ')
				}
				decrypt_text_stego(carrier, ref_text, password, seed_val, intensity, typo_chars, key_map, use_qwerty, overwrite, transpose, use_compression)!
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
		m := parse_mapping(mapping_str)
		noise_chars := get_noise_chars(nc_str)
		if mode_obf == '2' {
			result := apply_deobfuscation(text_input, m, noise_chars)
			println('\n' + term.bold(term.green('=== DE-OBFUSCATED TEXT ===\n' + result)))
		} else {
			result := apply_obfuscation(text_input, m, noise_int, noise_chars, seed_str)
			println('\n' + term.bold(term.green('=== OBFUSCATED TEXT ===\n' + result)))
		}
	}
}

fn main() {
	args := os.args
	if args.len == 1 {
		run_salty_interactive() or { println(term.red('Error: ${err}')) }
		return
	}
	if '-h' in args || '--help' in args {
		print_help()
		return
	}
	mode := args[1]
	if mode == 'interactive' {
		run_salty_interactive() or { println(term.red('Error: ${err}')) }
		return
	}
	if mode != 'encrypt' && mode != 'decrypt' && mode != 'obfuscate' {
		println(term.red('Error: Mode must be "encrypt", "decrypt" or "obfuscate"'))
		print_help()
		return
	}
	mut is_locktime := false
	for a in args {
		if a in ['--threads', '--mem', '--iter', '--out', '--pbkdf2-iter', '-sh', '--shred', '-s0', '--seed0', '-s1', '--seed1', '-s2', '--seed2'] {
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
	mut duration := u64(100000)
	mut mem := u32(65536)
	mut iter := u32(3)
	mut threads := u8(4)
	mut pbkdf2_iter := 200000
	mut shred_orig := false
	mut use_compression := false
	mut message := ''
	mut text_input := ''
	mut ref_text := ''
	mut password := ''
	mut seed0_str := ''
	mut seed1_str := ''
	mut seed2_str := ''
	mut seed_val := ''
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
				'-p', '--pass' { if i + 1 < args.len { password = args[i+1]; i++ } }
				'-s0', '--seed0' { if i + 1 < args.len { seed0_str = args[i+1]; i++ } }
				'-s1', '--seed1' { if i + 1 < args.len { seed1_str = args[i+1]; i++ } }
				'-s2', '--seed2' { if i + 1 < args.len { seed2_str = args[i+1]; i++ } }
				'--mem' { if i + 1 < args.len { mem = args[i+1].u32(); i++ } }
				'--iter' { if i + 1 < args.len { iter = args[i+1].u32(); i++ } }
				'--threads' { if i + 1 < args.len { threads = u8(args[i+1].int()); i++ } }
				'--pbkdf2-iter' { if i + 1 < args.len { pbkdf2_iter = args[i+1].int(); i++ } }
				'-sh', '--shred' { shred_orig = true }
				'-c', '--compress' { use_compression = true }
				else {}
			}
		}
		if password == '' {
			password = os.input_password('Enter Master Password: ') or { panic(err) }
		}
		if seed0_str == '' {
			seed0_str = os.input_password('Enter Seed 0 (Header Key): ') or { panic(err) }
		}
		if seed1_str == '' {
			seed1_str = os.input_password('Enter Seed 1 (VDF Key): ') or { panic(err) }
		}
		if seed2_str == '' {
			seed2_str = os.input_password('Enter Seed 2 (Payload Key): ') or { panic(err) }
		}
		if mode == 'encrypt' {
			locktime_encrypt_flow(file_path, out_path, duration, password, seed0_str, seed1_str, seed2_str, mem, iter, threads, pbkdf2_iter, shred_orig, use_compression) or {
				println(term.red('[-] Encryption Error: ${err}'))
			}
		} else if mode == 'decrypt' {
			locktime_decrypt_flow(file_path, out_path, password, seed0_str, seed1_str, seed2_str, pbkdf2_iter, shred_orig, use_compression) or {
				println(term.red('[-] Decryption Error: ${err}'))
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
				'-s', '--seed' { if i + 1 < args.len { seed_val = args[i + 1]; i++ } }
				'-f', '--formats' { if i + 1 < args.len { raw_formats = args[i + 1]; i++ } }
				'-ti', '--typo-intensity' { if i + 1 < args.len { typo_intensity = args[i + 1].int(); i++ } }
				'-tc', '--typo-chars' { if i + 1 < args.len { typo_chars = args[i + 1]; i++ } }
				'-km', '--key-map' { if i + 1 < args.len { key_map = args[i + 1]; i++ } }
				'-q', '--qwerty' { use_qwerty = true }
				'-o', '--overwrite' { overwrite = true }
				'-tr', '--transpose' { transpose = true }
				'-c', '--compress' { use_compression = true }
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
				println(term.red('Error: Text is required (-t or --text)'))
				return
			}
			if mapping_str == '' {
				println(term.red('Error: Mapping string is required (-map or --mapping)'))
				return
			}
			m := parse_mapping(mapping_str)
			noise_chars := get_noise_chars(noise_chars_str)
			if deobfuscate {
				result := apply_deobfuscation(text_input, m, noise_chars)
				println(term.bold(term.green('=== DE-OBFUSCATED TEXT ===\n' + result)))
			} else {
				result := apply_obfuscation(text_input, m, noise_intensity, noise_chars, seed_val)
				println(term.bold(term.green('=== OBFUSCATED TEXT ===\n' + result)))
			}
			return
		}
		if password == '' {
			println(term.red('Error: Password is required (-p or --pass)'))
			return
		}
		if raw_formats != '' {
			formats := parse_formats(raw_formats) or {
				println(term.red('Format parse error: ${err}'))
				return
			}
			if mode == 'encrypt' {
				if message == '' { println(term.red('Error: Message required (-m)')); return }
				encrypt_number_flow(message, password, seed_val, formats, use_compression) or { println(term.red('Encryption failed: ${err}')) }
			} else {
				if text_input == '' { println(term.red('Error: Carrier text required (-t)')); return }
				decrypt_number_flow(text_input, password, seed_val, formats, use_compression) or { println(term.red('Decryption failed: ${err}')) }
			}
		} else if typo_intensity > 0 {
			if mode == 'encrypt' {
				if message == '' { println(term.red('Error: Message required (-m)')); return }
				if text_input == '' { println(term.red('Error: Cover text required (-t)')); return }
				encrypt_text_stego(message, text_input, password, seed_val, typo_intensity, typo_chars.str(), key_map, use_qwerty, overwrite, transpose, use_compression) or { println(term.red('Encryption failed: ${err}')) }
			} else {
				if text_input == '' { println(term.red('Error: Carrier text required (-t)')); return }
				decrypt_text_stego(text_input, ref_text, password, seed_val, typo_intensity, typo_chars.str(), key_map, use_qwerty, overwrite, transpose, use_compression) or { println(term.red('Decryption failed: ${err}')) }
			}
		} else {
			println(term.red('Error: You must provide either --formats (for Number Mode) or --typo-intensity (for Text Mode).'))
			print_help()
		}
	}
}
