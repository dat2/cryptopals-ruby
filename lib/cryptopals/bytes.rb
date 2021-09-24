# typed: true
# frozen_string_literal: true

require 'sorbet-runtime'
require 'sorbet-struct-comparable'

module Cryptopals
  # Bytes is a wrapper around an array of integers with some helpful methods built in.
  class Bytes < T::Struct # rubocop:disable Metrics/ClassLength
    include T::Struct::ActsAsComparable

    extend T::Sig

    prop :bytes, T::Array[Integer]

    sig { params(length: Integer, default: Integer).returns(Bytes) }
    def self.fill(length, default)
      new(bytes: Array.new(length, default))
    end

    sig { params(str: String).returns(Bytes) }
    def self.from_string(str)
      new(bytes: str.bytes)
    end

    sig { params(str: String).returns(Bytes) }
    def self.from_hex(str)
      new(bytes: [str].pack('H*').bytes)
    end

    sig { params(input: String).returns(Bytes) }
    def self.from_base64(input)
      new(bytes: Base64.decode64(input).bytes)
    end

    sig { returns(String) }
    def to_s
      @bytes.pack('C*')
    end

    sig { returns(String) }
    def to_hex
      to_s.unpack1('H*')
    end

    sig { returns(String) }
    def to_base64
      @bytes.each_slice(3).to_a.map { |bytes| triplet_to_base64(bytes) }.join ''
    end

    sig { params(other: Bytes).returns(Bytes) }
    def ^(other)
      if @bytes.length != other.bytes.length
        raise ArgumentError, "Arrays are not of equal length: #{@bytes.length} != #{other.bytes.length}"
      end

      Bytes.new(bytes: @bytes.zip(other.bytes).map { |a, b| a ^ T.must(b) }.to_a)
    end

    sig { params(other: Bytes).returns(Integer) }
    def hamming_distance(other)
      @bytes.zip(other.bytes).reduce(0) do |acc, (first_byte, second_byte)|
        acc + (first_byte ^ T.must(second_byte)).to_s(2).count('1')
      end
    end

    sig { params(length: Integer).returns(Bytes) }
    def pkcs7_pad(length)
      pad = length - @bytes.length
      Bytes.new(bytes: @bytes.concat([pad] * pad))
    end

    sig { params(key: Bytes).returns(Bytes) }
    def aes_128_ecb_encrypt(key)
      raise ArgumentError, "plaintext not multiple of 16, #{@bytes.length}" unless (@bytes.length % 16).zero?

      cipher = OpenSSL::Cipher.new('aes-128-ecb')
      cipher.encrypt
      cipher.padding = 0
      cipher.key = key.to_s
      result = (cipher.update(to_s) + cipher.final)
      Bytes.new(bytes: result.bytes)
    end

    sig { params(key: Bytes).returns(Bytes) }
    def aes_128_ecb_decrypt(key)
      raise ArgumentError, "ciphertext not multiple of 16, #{@bytes.length}" unless (@bytes.length % 16).zero?

      cipher = OpenSSL::Cipher.new('aes-128-ecb')
      cipher.decrypt
      cipher.padding = 0
      cipher.key = key.to_s
      result = cipher.update(to_s) + cipher.final
      Bytes.new(bytes: result.bytes)
    end

    sig { params(key: Bytes, iv: Bytes).returns(Bytes) }
    def aes_128_cbc_decrypt(key, iv) # rubocop:disable Naming/MethodParameterName
      plaintext = []
      last_ciphertext = iv
      @bytes.each_slice(16).map { |bytes| Cryptopals::Bytes.new(bytes: bytes) }.each do |block|
        plaintext.concat((block.aes_128_ecb_decrypt(key) ^ last_ciphertext).bytes)
        last_ciphertext = block
      end
      Bytes.new(bytes: plaintext)
    end

    sig { returns(Integer) }
    def length
      @bytes.length
    end

    sig { params(length: Integer).returns(Bytes) }
    def repeat(length)
      num_cycles = length.fdiv(@bytes.length).ceil
      Bytes.new(bytes: @bytes.cycle(num_cycles).take(length).to_a)
    end

    sig { params(size: Integer).returns(T::Array[Bytes]) }
    def chunks(size)
      @bytes.each_slice(size).map { |bytes| Bytes.new(bytes: bytes) }
    end

    sig { params(size: Integer).returns(T::Array[Bytes]) }
    def transpose(size)
      matrix = chunks(size)
      matrix.each_index.map do |row|
        Bytes.new(bytes: matrix.each_index.map do |column|
          T.must(matrix[column]).bytes.fetch(row, nil)
        end.compact)
      end
    end

    private

    sig { params(num: Integer).returns(String) }
    def sextet_to_base64(num) # rubocop:disable Metrics/MethodLength
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

    sig { params(bytes: T::Array[Integer]).returns(String) }
    def triplet_to_base64(bytes) # rubocop:disable Metrics/AbcSize
      first = T.must(bytes[0]) >> 2
      second = (T.must(bytes[0]) & 0x03) << 4 | T.must(bytes[1]) >> 4
      third = ((T.must(bytes[1]) & 0x0F) << 2) | T.must(bytes[2]) >> 6
      fourth = T.must(bytes[2]) & 0x3F
      [first, second, third, fourth].map { |value| sextet_to_base64(value) }.join ''
    end
  end
end
