# typed: true
# frozen_string_literal: true

require 'sorbet-runtime'

module Cryptopals
  extend T::Sig

  sig { params(num: Integer).returns(String) }
  def self.sextet_to_base64(num)
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
    T.must(ascii).chr
  end

  sig { params(bytes: T::Array[Integer]).returns(String) }
  def self.triplet_to_base64(bytes)
    first = T.must(bytes[0]) >> 2
    second = (bytes[0] & 0x03) << 4 | T.must(bytes[1]) >> 4
    third = ((bytes[1] & 0x0F) << 2) | T.must(bytes[2]) >> 6
    fourth = bytes[2] & 0x3F
    [first, second, third, fourth].map { |value| sextet_to_base64(value) }.join ''
  end

  sig { params(input: String).returns(String) }
  def self.hex_to_base64(input)
    [input].pack('H*').bytes.each_slice(3).to_a.map { |bytes| triplet_to_base64(bytes) }.join ''
  end
end
