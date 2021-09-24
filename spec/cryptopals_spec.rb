# typed: false
# frozen_string_literal: true

require 'cryptopals'
require 'base64'

describe Cryptopals::Bytes do
  describe '#to_base64' do
    it 'converts to base64 correctly' do
      # rubocop:disable Layout/LineLength
      bytes = Cryptopals::Bytes.from_hex '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'
      # rubocop:enable Layout/LineLength
      expect(bytes.to_base64).to eq 'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'
    end
  end

  describe 'xor' do
    it 'xors the input corrrectly' do
      first = Cryptopals::Bytes.from_hex '1c0111001f010100061a024b53535009181c'
      second = Cryptopals::Bytes.from_hex '686974207468652062756c6c277320657965'
      result = first ^ second
      expected = Cryptopals::Bytes.from_hex '746865206b696420646f6e277420706c6179'

      expect(result).to eq expected
    end
  end

  describe '#repeat' do
    it 'works' do
      input = Cryptopals::Bytes.new(bytes: [1, 2])

      expect(input.repeat(5)).to eq(Cryptopals::Bytes.new(bytes: [1,2,1,2,1]))
    end

  end

  describe '#transpose' do
    it 'works' do
      input = Cryptopals::Bytes.new(bytes: (1..8).to_a)

      expect(input.transpose(3)).to eq([
                                         Cryptopals::Bytes.new(bytes: [1, 4, 7]),
                                         Cryptopals::Bytes.new(bytes: [2, 5, 8]),
                                         Cryptopals::Bytes.new(bytes: [3, 6])
                                       ])
    end
  end
end

describe Cryptopals, '#decrypt_fixed_xor' do
  it 'finds the answer' do
    bytes = Cryptopals::Bytes.from_hex '1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'

    result = Cryptopals.decrypt_fixed_xor bytes

    expect(result.to_s).to eq('Cooking MC\'s like a pound of bacon')
  end
end

describe Cryptopals, '#break_fixed_xor' do
  it 'finds the answer' do
    ciphertexts = IO.readlines('4.txt', chomp: true).map { |line| Cryptopals::Bytes.from_hex line }

    result = Cryptopals.break_fixed_xor ciphertexts

    expect(result.to_s).to eq("Now that the party is jumping\n")
  end
end

describe Cryptopals, '#encrypt_repeating_key_xor' do
  it 'encrypts correctly' do
    # rubocop:disable Layout/LineLength
    plaintext = Cryptopals::Bytes.from_string("Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal")
    # rubocop:enable Layout/LineLength
    key = Cryptopals::Bytes.from_string('ICE')

    result = Cryptopals.repeating_key_xor plaintext, key
    # rubocop:disable Layout/LineLength
    expected = Cryptopals::Bytes.from_hex '0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f'
    # rubocop:enable Layout/LineLength
    expect(result).to eq expected
  end
end

describe Cryptopals, '#hamming_distance' do
  it 'works correctly' do
    left = Cryptopals::Bytes.from_string('this is a test')
    right = Cryptopals::Bytes.from_string('wokka wokka!!!')

    expect(left.hamming_distance(right)).to eq 37
  end
end

describe Cryptopals, '#break_repeating_key_xor' do
  it 'finds the answer' do
    ciphertext = Cryptopals::Bytes.from_base64(IO.readlines('6.txt', chomp: true).join(''))

    expected = IO.readlines('6_result.txt').join('')

    result = Cryptopals.break_repeating_key_xor(ciphertext)

    expect(result.key.to_s).to eq('Terminator X: Bring the noise')
    expect(result.to_s).to eq(expected)
  end
end

describe Cryptopals, '#aes_128_ecb_decrypt' do
  it 'works' do
    plaintext = Cryptopals::Bytes.from_string('orange submarine')
    key = Cryptopals::Bytes.from_string('YELLOW SUBMARINE')

    result = plaintext.aes_128_ecb_encrypt(key).aes_128_ecb_decrypt(key)

    expect(result).to eq(plaintext)
  end
end

describe Cryptopals, '#find_index_aes_128_ecb' do
  it 'finds the right one' do
    ciphertexts = IO.readlines('8.txt', chomp: true).map { |hex_string| Cryptopals::Bytes.from_hex(hex_string) }

    result = Cryptopals.find_index_aes_128_ecb(ciphertexts)

    expect(result).to eq(132)
  end
end

describe Cryptopals, '#pkcs7_pad' do
  it 'is correct' do
    result = Cryptopals::Bytes.from_string('YELLOW SUBMARINE').pkcs7_pad(20)
    expected = "YELLOW SUBMARINE\x04\x04\x04\x04"
    expect(result.to_s).to eq(expected)
  end
end

describe Cryptopals, '#aes_128_cbc_decrypt' do
  it 'works' do
    ciphertext = Cryptopals::Bytes.from_base64(IO.readlines('10.txt', chomp: true).join(''))
    key = Cryptopals::Bytes.from_string('YELLOW SUBMARINE')
    iv = Cryptopals::Bytes.new(bytes: [0] * 16)

    result = ciphertext.aes_128_cbc_decrypt(key, iv)

    expected_result = Cryptopals::Bytes.from_string(File.open('10_result.txt').read)
    pad_length = expected_result.length + expected_result.length % 16
    expected = expected_result.pkcs7_pad(pad_length)

    expect(result).to eq(expected)
  end
end
