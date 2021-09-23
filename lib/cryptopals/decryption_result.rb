# typed: true
# frozen_string_literal: true

require 'sorbet-runtime'
require 'sorbet-struct-comparable'
require_relative 'bytes'

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

module Cryptopals
  # DecryptionResult stores the ciphertext, plaintext, and key that decrypted the ciphertext to the plaintext.
  class DecryptionResult < T::Struct
    include T::Struct::ActsAsComparable

    extend T::Sig

    const :ciphertext, Bytes
    const :plaintext, Bytes
    const :key, Bytes

    sig { returns(Float) }
    def error
      plaintext = @plaintext.to_s.downcase

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
      @plaintext.to_s
    end
  end
end
