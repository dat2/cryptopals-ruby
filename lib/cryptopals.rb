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
      key = Bytes.fill(ciphertext.length, key_candidate)
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
    plaintext ^ key.repeat(plaintext.length)
  end

  sig { params(input: T::Array[Integer]).returns(Float) }
  def self.average(input)
    input.sum.fdiv(input.size)
  end

  sig { params(input: Bytes).returns(T::Array[Integer]) }
  def self.keysizes(input)
    (2..40).sort_by do |keysize|
      distances = input.chunks(keysize).take(4).each_slice(2).map do |first, second|
        T.must(first).hamming_distance(T.must(second))
      end
      average(distances) / keysize
    end
  end

  sig { params(ciphertext: Bytes).returns(DecryptionResult) }
  def self.break_repeating_key_xor(ciphertext)
    results = keysizes(ciphertext).map do |keysize|
      key_bytes = ciphertext.transpose(keysize).map do |block|
        decrypt_fixed_xor(block).key.bytes.first
      end.compact
      key = Cryptopals::Bytes.new(bytes: key_bytes)
      DecryptionResult.new(ciphertext: ciphertext, plaintext: repeating_key_xor(ciphertext, key), key: key)
    end
    T.must(results.min_by(&:error))
  end

  sig { params(ciphertexts: T::Array[Bytes]).returns(Integer) }
  def self.find_index_aes_128_ecb(ciphertexts)
    T.must(ciphertexts.find_index do |ciphertext|
      slices = ciphertext.chunks(16)
      slices.uniq.length != slices.length
    end)
  end

  # encryption type exists so we can do type checking on the return value of detect_encryption_type
  class EncryptionType < T::Enum
    enums do
      CBC = new
      ECB = new
      UNKNOWN = new
    end
  end

  # this class stores the ciphertext and the type of encryption we used on it.
  class EncryptionOracleResult < T::Struct
    const :ciphertext, Bytes
    const :type, EncryptionType
  end

  sig { params(plaintext: Bytes).returns(EncryptionOracleResult) }
  def self.encryption_oracle(plaintext) # rubocop:disable Metrics/MethodLength
    key = Cryptopals::Bytes.random(16)
    before = Cryptopals::Bytes.random(rand(5..10))
    after = Cryptopals::Bytes.random(rand(5..10))

    plaintext_to_encrypt = (before + plaintext + after).pkcs7_pad_to(16)

    if rand(2).zero?
      EncryptionOracleResult.new(ciphertext: plaintext_to_encrypt.aes_128_ecb_encrypt(key), type: EncryptionType::ECB)
    else
      iv = Cryptopals::Bytes.random(16)
      EncryptionOracleResult.new(ciphertext: plaintext_to_encrypt.aes_128_cbc_encrypt(key, iv),
                                 type: EncryptionType::CBC)
    end
  end

  sig { params(ciphertext: Bytes).returns(EncryptionType) }
  def self.detect_encryption_type(ciphertext)
    chunks = ciphertext.chunks(16)
    if chunks.uniq.length != chunks.length
      EncryptionType::ECB
    else
      EncryptionType::CBC
    end
  end
end
