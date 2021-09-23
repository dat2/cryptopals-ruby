# typed: true
# frozen_string_literal: true

require 'sorbet-runtime'
require 'pp'
require 'openssl'
require 'cryptopals/bytes'
require 'cryptopals/decryption_result'

module Cryptopals # rubocop:disable Style/Documentation
  extend T::Sig

  sig { params(ciphertext: Bytes).returns(T::Array[DecryptionResult]) }
  def self.decrypt_ciphertext_candidates(ciphertext)
    key_candidates = [
      *'a'..'z',
      *'A'..'Z',
      *'0'..'9',
      *"!@\#$%^&*() :".chars
    ].map(&:ord)
    key_candidates.map do |key_candidate|
      key = Bytes.new(bytes: Array.new(ciphertext.length, key_candidate))
      DecryptionResult.new(ciphertext: ciphertext, plaintext: key ^ ciphertext, key: key)
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
    plaintext ^ (key.repeat(plaintext.length).take(plaintext.length))
  end

  sig { params(input: T::Array[Integer]).returns(Float) }
  def self.average(input)
    input.sum.fdiv(input.size)
  end

  sig { params(input: Bytes).returns(T::Array[Integer]) }
  def self.keysizes(input)
    (2..40).sort_by do |keysize|
      distances = input.bytes.each_slice(keysize).take(4).each_slice(2).map do |first, second|
        Cryptopals::Bytes.new(bytes: T.must(first)).hamming_distance(Cryptopals::Bytes.new(bytes: T.must(second)))
      end
      average(distances) / keysize
    end
  end

  sig { params(ciphertext: Bytes, keysize: Integer).returns(T::Array[Bytes]) }
  def self.transpose(ciphertext, keysize)
    blocks = ciphertext.bytes.each_slice(keysize).to_a
    blocks[0].zip(*T.unsafe(blocks[1..])).map(&:compact)
  end

  sig { params(ciphertext: Bytes).returns(DecryptionResult) }
  def self.break_repeating_key_xor(ciphertext)
    results = keysizes(ciphertext).map do |keysize|
      key_bytes = transpose(ciphertext, keysize).map do |block|
        decrypt_fixed_xor(block)
      end
      key = Cryptopals::Bytes.new(bytes: key_bytes.map(&:key).map(&:bytes).map(&:first))
      DecryptionResult.new(ciphertext: ciphertext, plaintext: repeating_key_xor(ciphertext, key), key: key)
    end
    T.must(results.min_by(&:error))
  end

  sig { params(ciphertexts: T::Array[Bytes]).returns(Integer) }
  def self.find_index_aes_128_ecb(ciphertexts)
    T.must(ciphertexts.find_index do |ciphertext|
      slices = ciphertext.bytes.each_slice(16).to_a
      slices.uniq.length != slices.length
    end)
  end
end
