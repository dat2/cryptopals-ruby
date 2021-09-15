# typed: true
# frozen_string_literal: true

require 'sorbet-runtime'
require 'pp'
require 'openssl'

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

  class DecryptionResult # :nodoc:
    extend T::Sig

    attr_reader :plaintext, :key

    sig { params(plaintext: Bytes, key: Bytes).void }
    def initialize(plaintext, key)
      @plaintext = plaintext
      @key = key
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

    sig { returns(Float) }
    def error
      plaintext = Cryptopals.to_ascii(@plaintext).downcase

      # if there are too many non english characters, this is probably not an english sentence
      penalty = plaintext.tr("a-z '", '').length

      ENGLISH_LETTER_FREQUENCIES.reduce(penalty) do |total, (letter, standard_frequency)|
        # if the frequency of the letters are too different from typical letter frequencies
        # it's probably not an englishsentence
        letter_frequency = plaintext.count(letter.to_s).fdiv(plaintext.length)
        total + (letter_frequency - standard_frequency).abs
      end
    end

    def to_s
      Cryptopals.to_ascii(@plaintext)
    end

    def inspect
      "DecryptionResult(plaintext=#{Cryptopals.to_ascii(@plaintext)}, key=#{Cryptopals.to_ascii(@key)})"
    end
  end

  sig { params(ciphertext: Bytes).returns(T::Array[DecryptionResult]) }
  def self.decrypt_ciphertext_candidates(ciphertext)
    key_candidates = [
      *'a'..'z',
      *'A'..'Z',
      *'0'..'9',
      *"!@\#$%^&*() :".chars
    ].map(&:ord)
    key_candidates.map do |key_candidate|
      key = Array.new(ciphertext.length, key_candidate)
      DecryptionResult.new(fixed_xor(key, ciphertext), key)
    end
  end

  sig { params(ciphertext: Bytes).returns(DecryptionResult) }
  def self.decrypt_fixed_xor(ciphertext)
    T.must(decrypt_ciphertext_candidates(ciphertext).min_by(&:error))
  end

  sig { params(ciphertexts: T::Array[Bytes]).returns(DecryptionResult) }
  def self.break_fixed_xor(ciphertexts)
    T.must(ciphertexts.flat_map { |ciphertext| decrypt_ciphertext_candidates(ciphertext) }.min_by(&:error))
  end

  sig { params(plaintext: Bytes, key: Bytes).returns(Bytes) }
  def self.repeating_key_xor(plaintext, key)
    fixed_xor(plaintext, key.cycle(plaintext.length).take(plaintext.length))
  end

  sig { params(first: Bytes, second: Bytes).returns(Integer) }
  def self.hamming_distance(first, second)
    first.zip(second).reduce(0) do |acc, (first_byte, second_byte)|
      acc + (first_byte ^ T.must(second_byte)).to_s(2).count('1')
    end
  end

  sig { params(input: T::Array[Integer]).returns(Float) }
  def self.average(input)
    input.sum.fdiv(input.size)
  end

  sig { params(input: Bytes).returns(T::Array[Integer]) }
  def self.keysizes(input)
    (2..40).sort_by do |keysize|
      distances = input.each_slice(keysize).take(4).each_slice(2).map do |first, second|
        hamming_distance(T.must(first), T.must(second))
      end
      average(distances) / keysize
    end
  end

  sig { params(ciphertext: Bytes, keysize: Integer).returns(T::Array[Bytes]) }
  def self.transpose(ciphertext, keysize)
    blocks = ciphertext.each_slice(keysize).to_a
    blocks[0].zip(*T.unsafe(blocks[1..])).map(&:compact)
  end

  sig { params(ciphertext: Bytes).returns(DecryptionResult) }
  def self.break_repeating_key_xor(ciphertext)
    results = keysizes(ciphertext).map do |keysize|
      key_bytes = transpose(ciphertext, keysize).map do |block|
        decrypt_fixed_xor(block)
      end
      key = key_bytes.map(&:key).map(&:first)
      DecryptionResult.new(repeating_key_xor(ciphertext, key), key)
    end
    T.must(results.min_by(&:error))
  end

  sig { params(ciphertext: String, key: String).returns(String) }
  def self.aes_128_ecb_decrypt(ciphertext, key)
    cipher = OpenSSL::Cipher.new('aes-128-ecb').decrypt
    cipher.key = key
    cipher.update(ciphertext) + cipher.final
  end

  sig { params(ciphertexts: T::Array[Bytes]).returns(Integer) }
  def self.find_index_aes_128_ecb(ciphertexts)
    T.must(ciphertexts.find_index do |ciphertext|
      slices = ciphertext.each_slice(16).to_a
      slices.uniq.length != slices.length
    end)
  end
end
