# typed: false
# frozen_string_literal: true

require 'cryptopals'

describe Cryptopals, '#to_base64' do
  it 'converts to base64 correctly' do
    # rubocop:disable Layout/LineLength
    bytes = Cryptopals.to_bytes '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'
    # rubocop:enable Layout/LineLength
    result = Cryptopals.to_base64 bytes
    expect(result).to eq 'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'
  end
end

describe Cryptopals, '#fixed_xor' do
  it 'xors the input corrrectly' do
    first = Cryptopals.to_bytes '1c0111001f010100061a024b53535009181c'
    second = Cryptopals.to_bytes '686974207468652062756c6c277320657965'
    result = Cryptopals.fixed_xor(
      first,
      second
    )
    expected = Cryptopals.to_bytes '746865206b696420646f6e277420706c6179'

    expect(result).to eq expected
  end
end

describe Cryptopals, '#xor_decrypt' do
  it 'finds the answer' do
    bytes = Cryptopals.to_bytes '1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'
    result = Cryptopals.xor_decrypt bytes

    expect(result).to eq 'Cooking MC\'s like a pound of bacon'
  end
end

describe Cryptopals, '#search_xor_decrypt' do
  it 'finds the answer' do
    ciphertexts = IO.readlines('4.txt', chomp: true).map { |line| Cryptopals.to_bytes line }

    result = Cryptopals.search_xor_decrypt ciphertexts
    expect(result).to eq 'Now that the party is jumping\n'
  end
end
