# typed: true
# frozen_string_literal: true

require 'sorbet-runtime'
require 'pp'

module Cryptopals # rubocop:disable Style/Documentation,Metrics/ModuleLength
  extend T::Sig

  Bytes = T.type_alias { T::Array[Integer] }

  sig { params(string: String).returns(Bytes) }
  def self.to_bytes(string)
    [string].pack('H*').bytes
  end

  sig { params(bytes: Bytes).returns(String) }
  def self.to_hex(bytes)
    bytes.pack('C*').unpack1('H*')
  end

  sig { params(bytes: Bytes).returns(String) }
  def self.to_ascii(bytes)
    bytes.pack('C*')
  end

  sig { params(num: Integer).returns(String) }
  def self.sextet_to_base64(num) # rubocop:disable Metrics/MethodLength
    ascii = case num
            when 0..25
              ('A'.ord + num)
            when 26..51
              ('a'.ord + (num - 26))
            when 52..61
              ('0'.ord + (num - 52))
            when 62
              '+'.ord
            when 63
              '/'.ord
            else raise ArgumentError, "#{num} is not valid."
            end
    T.let(ascii, Integer).chr
  end

  sig { params(bytes: Bytes).returns(String) }
  def self.triplet_to_base64(bytes) # rubocop:disable Metrics/AbcSize
    first = T.must(bytes[0]) >> 2
    second = (T.must(bytes[0]) & 0x03) << 4 | T.must(bytes[1]) >> 4
    third = ((T.must(bytes[1]) & 0x0F) << 2) | T.must(bytes[2]) >> 6
    fourth = T.must(bytes[2]) & 0x3F
    [first, second, third, fourth].map { |value| sextet_to_base64(value) }.join ''
  end

  sig { params(input: Bytes).returns(String) }
  def self.to_base64(input)
    input.each_slice(3).to_a.map { |bytes| triplet_to_base64(bytes) }.join ''
  end

  sig { params(first: Bytes, second: Bytes).returns(Bytes) }
  def self.fixed_xor(first, second)
    if first.length != second.length
      raise ArgumentError, "Arrays are not of equal length: #{first.length} != #{second.length}"
    end

    first.zip(second).map { |a, b| a ^ T.must(b) }.to_a
  end

  # https://en.wikipedia.org/wiki/Letter_frequency
  ENGLISH_LETTER_FREQUENCIES = {
    a: 0.082,
    b: 0.015,
    c: 0.028,
    d: 0.043,
    e: 0.13,
    f: 0.022,
    g: 0.02,
    h: 0.061,
    i: 0.07,
    j: 0.0015,
    k: 0.0077,
    l: 0.04,
    m: 0.024,
    n: 0.067,
    o: 0.075,
    p: 0.019,
    q: 0.000095,
    r: 0.06,
    s: 0.063,
    t: 0.091,
    u: 0.028,
    v: 0.0098,
    w: 0.024,
    x: 0.0015,
    y: 0.02,
    z: 0.00074
  }.freeze

  sig { params(plaintext: String).returns(Float) }
  def self.error_score(plaintext)
    # if there are too many non english characters, this is probably not an english sentence
    count_special_characters = plaintext.tr('a-z', '').tr(' ', '').length

    ENGLISH_LETTER_FREQUENCIES.reduce(count_special_characters) do |total, (letter, standard_frequency)|
      # if the frequency of the letters are too different from typical letter frequencies
      # it's probably not an englishsentence
      letter_frequency = plaintext.count(letter.to_s).to_f / plaintext.length
      total + (letter_frequency - standard_frequency).abs
    end
  end

  sig { params(ciphertext: Bytes).returns(T::Array[String]) }
  def self.decrypt_ciphertext_candidates(ciphertext)
    key_candidates = [].concat(('a'..'z').to_a, ('A'..'Z').to_a, ('0'..'9').to_a,
                               ["!@#$%^&*()_+-=~`[]{}\\|;:\"',./<>?"]).to_a
    key_candidates.map do |key_candidate|
      key = Array.new(ciphertext.length, key_candidate.ord)
      to_ascii(fixed_xor(key, ciphertext))
    end
  end

  sig { params(ciphertext: Bytes).returns(String) }
  def self.xor_decrypt(ciphertext)
    plaintexts = decrypt_ciphertext_candidates(ciphertext)
    T.must(plaintexts.min_by { |plaintext| error_score(plaintext) })
  end

  sig { params(ciphertexts: T::Array[Bytes]).returns(String) }
  def self.search_xor_decrypt(ciphertexts)
    plaintexts = ciphertexts.flat_map { |ciphertext| decrypt_ciphertext_candidates(ciphertext) }
    T.must(plaintexts.min_by { |plaintext| error_score(plaintext) })
  end

  sig { params(key: Bytes, length: Integer).returns(Bytes) }
  def self.derive_key(key, length)
    (key * length).take(length)
  end

  sig { params(plaintext: Bytes, key: Bytes).returns(Bytes) }
  def self.encrypt_xor(plaintext, key)
    fixed_xor(plaintext, derive_key(key, plaintext.length))
  end
end
